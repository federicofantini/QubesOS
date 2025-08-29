from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import ipaddress
from typing import List, Tuple, Optional, Dict

from django.conf import settings
from django.db import transaction
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.views import View

from .models import Pr0cksConfig, VM, RouteBinding

PR0CKS_BIN = getattr(settings, "PR0CKS_BIN", "/home/unpriv/go/bin/pr0cks")
IPTABLES = getattr(settings, "IPTABLES", "/usr/sbin/iptables")
SUDO_BIN = getattr(settings, "SUDO_BIN", "/usr/bin/sudo")

SS_TIMEOUT = 3.0
RUN_TIMEOUT = 4.0
MAX_IMPORT_ITEMS = 1000

# ---------------- Validation ----------------
def is_valid_ip_port(value: str) -> bool:
    if not value or ":" not in value:
        return False
    host, _, port_s = value.rpartition(":")
    try:
        port = int(port_s)
        if not (1 <= port <= 65535):
            return False
    except ValueError:
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True

def is_valid_host_port(value: str) -> bool:
    if not value or ":" not in value:
        return False
    host, _, port_s = value.rpartition(":")
    try:
        port = int(port_s)
        if not (1 <= port <= 65535):
            return False
    except ValueError:
        return False
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return len(host) <= 253

def _parse_host_port(s: str) -> tuple[str, int]:
    s = (s or "").strip()
    if not s or ":" not in s:
        raise ValueError("Expected host:port")
    if s[0] == "[":  # format [IPv6]:port
        rb = s.find("]")
        if rb == -1 or rb + 1 >= len(s) or s[rb + 1] != ":":
            raise ValueError("Bad [IPv6]:port format")
        host = s[1:rb]
        port = int(s[rb + 2:])
    else:           # host (or IPv4) + ":" + port
        host, port_str = s.rsplit(":", 1)
        port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError("Port out of range")
    return host, port

def _check_binaries() -> Nones:
    if not (os.path.isfile(PR0CKS_BIN)):
        raise RuntimeError(f"Binary not exits: {PR0CKS_BIN}")
    if not os.access(PR0CKS_BIN, os.X_OK):
        raise RuntimeError(f"Binary not executable: {PR0CKS_BIN}")
    if not (os.path.isfile(IPTABLES)):
        raise RuntimeError(f"Binary not exits: {IPTABLES}")
    if not os.access(IPTABLES, os.X_OK):
        raise RuntimeError(f"Binary not executable: {IPTABLES}")
    if not (os.path.isfile(SUDO_BIN)):
        raise RuntimeError(f"Binary not exits: {SUDO_BIN}")
    if not os.access(SUDO_BIN, os.X_OK):
        raise RuntimeError(f"Binary not executable: {SUDO_BIN}")

def bridge_for_ip(ip: str) -> str:
    try:
        out = subprocess.check_output(["ip", "-j", "route", "get", ip], text=True)
        routes = json.loads(out)
        dev = routes[0].get("dev")
        if not dev:
            raise RuntimeError("no dev in route")
        return dev
    except Exception as e:
        raise RuntimeError(f"unable to determinate the interface for the IP address {ip}: {e}")

def gateway_for_ip(ip: str) -> str:
    try:
        out = subprocess.check_output(["ip", "-j", "route", "get", ip], text=True)
        route = json.loads(out)[0]
        return route.get("gateway") or route.get("prefsrc") or route.get("src")
    except Exception as e:
        raise RuntimeError(f"unable to determinate the gateway for the IP address {ip}: {e}")

# ---------------- iptables helpers ----------------
def _sudo_prefix() -> List[str]:
    try:
        if os.geteuid() == 0:
            return []
    except AttributeError:
        pass
    return [SUDO_BIN, "-n"]

def _run(cmd: List[str], timeout: float = RUN_TIMEOUT) -> Tuple[int, str, str]:
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        return 124, "", "timeout"
    return p.returncode, out, err

def _ipt(nat: bool = False) -> List[str]:
    base = _sudo_prefix() + [IPTABLES]
    if nat:
        base += ["-t", "nat"]
    return base

def _exists(*args: str, nat: bool = False) -> bool:
    rc, _, _ = _run(_ipt(nat=nat) + ["-C", *args])
    return rc == 0

def _add_if_missing(args: List[str], nat: bool = False) -> str:
    """
    Returns:
      - "exists" if the rule already exists
      - "added"  if the rule has been added
    Throws RuntimeError in case of failure.
    """
    if _exists(*args, nat=nat):
        return "exists"
    rc, out, err = _run(_ipt(nat=nat) + ["-A", *args])
    if rc == 0:
        return "added"
    raise RuntimeError(err or out or "iptables -A failed")

def _del_if_present(args: List[str], nat: bool = False) -> bool:
    rc, _, _ = _run(_ipt(nat=nat) + ["-D", *args])
    return rc == 0

def _del_all_by_tag(tag: str) -> int:
    """Remove all the rules (filter/nat) that contains --comment tag."""
    removed_total = 0
    for nat in (False, True):
        rc, out, _ = _run(_ipt(nat=nat) + ["-S"])
        if rc != 0:
            continue
        while True:
            lines = [ln for ln in out.splitlines() if ln.startswith("-A ") and tag in ln]
            if not lines:
                break
            for ln in lines:
                toks = shlex.split(ln)
                if len(toks) < 3:
                    continue
                chain, spec = toks[1], toks[2:]
                rc2, _, _ = _run(_ipt(nat=nat) + ["-D", chain, *spec])
                if rc2 == 0:
                    removed_total += 1
            rc, out, _ = _run(_ipt(nat=nat) + ["-S"])
            if rc != 0:
                break
    return removed_total

def build_rules(ip: str, proxy_port: int, dns_port: int, remote_ip: str, remote_port: str, tag: str) -> List[Tuple[List[str], bool]]:
    assert 1 <= proxy_port <= 65535 and 1 <= dns_port <= 65535

    ipaddress.ip_address(ip)
    ipaddress.ip_address(remote_ip)

    isolated_br = bridge_for_ip(ip)
    isolated_gateway = gateway_for_ip(ip)
    natted_br = bridge_for_ip(remote_ip)

    rules: List[Tuple[List[str], bool]] = []

    # INPUT from isolated net: allows only pr0cks, drop all the rest
    rules.append((["INPUT", "-i", isolated_br, "-d", isolated_gateway, "-p", "tcp", "--dport", str(proxy_port), "-m", "comment", "--comment", tag, "-j", "ACCEPT"], False))
    rules.append((["INPUT", "-i", isolated_br, "-d", isolated_gateway, "-p", "udp", "--dport", str(dns_port), "-m", "comment", "--comment", tag, "-j", "ACCEPT"], False))
    rules.append((["INPUT", "-i", isolated_br, "-m", "comment", "--comment", tag, "-j", "DROP"], False))

    # INPUT from NAT net: allows only replies from already started connections by the host
    rules.append((["INPUT", "-i", natted_br, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", tag, "-j", "ACCEPT"], False))
    rules.append((["INPUT", "-i", natted_br, "-m", "comment", "--comment", tag, "-j", "DROP"], False))

    # PREROUTING: redirect all traffic to pr0cks port. (note: pr0cks must listen on the same interface of source IP address)
    rules.append((["PREROUTING", "-s", ip, "-p", "tcp", "--dport", "53", "-m", "comment", "--comment", tag, "-j", "REDIRECT", "--to-ports", str(dns_port)], True))
    rules.append((["PREROUTING", "-s", ip, "-p", "udp", "--dport", "53", "-m", "comment", "--comment", tag, "-j", "REDIRECT", "--to-ports", str(dns_port)], True))
    rules.append((["PREROUTING", "-s", ip, "-p", "tcp", "!", "--dport", "53", "-m", "comment", "--comment", tag, "-j", "REDIRECT", "--to-ports", str(proxy_port)], True))
    rules.append((["PREROUTING", "-s", ip, "-p", "udp", "!", "--dport", "53", "-m", "comment", "--comment", tag, "-j", "REDIRECT", "--to-ports", str(proxy_port)], True))

    # Guard rail between bridges
    rules.append((["FORWARD", "-i", isolated_br, "-o", natted_br, "-m", "comment", "--comment", tag, "-j", "DROP"], False))
    rules.append((["FORWARD", "-i", natted_br, "-o", isolated_br, "-m", "comment", "--comment", tag, "-j", "DROP"], False))

    # OUTPUT from vm ip: drop all traffic not covered by REDIRECT rule
    rules.append((["OUTPUT", "-s", ip, "-m", "comment", "--comment", tag, "-j", "DROP"], False))
    # OUTPUT to NAT net: allows only traffic to SOCKS port
    rules.append((["OUTPUT", "-o", natted_br, "-d", remote_ip, "-p", "tcp", "--dport", str(remote_port), "-m", "comment", "--comment", tag, "-j", "ACCEPT"], False))
    rules.append((["OUTPUT", "-o", natted_br, "-m", "comment", "--comment", tag, "-j", "DROP"], False))

    return rules

def enable_binding(binding: RouteBinding) -> Dict[str, object]:
    vm = binding.vm
    if not (vm.ip and vm.ip.strip()):
        return {"ok": False, "error": f"VM '{vm.name}' has no IP"}
    ip = vm.ip.strip()
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return {"ok": False, "error": f"Invalid IP '{vm.ip}'"}

    tag = binding.tag()
    remote_ip, remote_port = _parse_host_port(binding.pr0cks.remote_socks5)
    rules = build_rules(ip, binding.proxy_port, binding.dns_port, remote_ip, remote_port, tag)

    created = exists = 0
    errors: List[str] = []
    for args, is_nat in rules:
        try:
            res = _add_if_missing(args, nat=is_nat)
            if res == "added":
                created += 1
            else:
                exists += 1
        except Exception as e:
            errors.append(f"{'nat ' if is_nat else ''}{args}: {e}")

    if errors:
        return {"ok": False, "created": created, "exists": exists, "errors": errors}

    binding.enabled = True
    binding.save(update_fields=["enabled", "updated_at"])
    return {"ok": True, "created": created, "exists": exists}

def disable_binding(binding: RouteBinding) -> Dict[str, object]:
    tag = binding.tag()
    try:
        removed = _del_all_by_tag(tag)
    except Exception as e:
        return {"ok": False, "removed": 0, "errors": [str(e)]}

    binding.enabled = False
    binding.save(update_fields=["enabled", "updated_at"])
    return {"ok": True, "removed": removed}

# ---------------- pr0cks process helpers ----------------
def _refresh_socket_status() -> Dict[str, Dict[str, int]]:
    try:
        ps = subprocess.Popen(["ss", "-tupln"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, _ = ps.communicate(timeout=SS_TIMEOUT)
    except Exception:
        return {}
    if ps.returncode not in (0, None):
        return {}
    SS = {}
    for line in output.splitlines():
        if "pr0cks" not in line:
            continue
        parts = re.sub(r" +", " ", line.strip()).split()
        if len(parts) < 5:
            continue
        addr = parts[4]
        m = re.search(r"pid=(\d+)", line)
        if not m:
            continue
        try:
            SS[addr] = {"transport": parts[0], "pid": int(m.group(1))}
        except Exception:
            continue
    return SS

def _sync_pids_with_ss() -> None:
    SS = _refresh_socket_status()
    addr2pid = {addr: info["pid"] for addr, info in SS.items()}
    for cfg in Pr0cksConfig.objects.all():
        new_pid = None
        if cfg.local_proxy in addr2pid:
            new_pid = addr2pid[cfg.local_proxy]
        elif cfg.local_dns in addr2pid:
            new_pid = addr2pid[cfg.local_dns]
        if cfg.pid != new_pid:
            cfg.pid = new_pid
            cfg.save(update_fields=["pid", "updated_at"])

def _start_pr0cks(local_proxy: str, local_dns: str, remote_socks5: str) -> int:
    _check_binaries()
    cmd = [PR0CKS_BIN, "-v", "-lproxy", local_proxy, "-ldns", local_dns, "-socks5", remote_socks5]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return proc.pid

def _kill_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass

# ---------------- View ----------------
class RunPr0cksView(View):
    def get(self, request):
        if (request.GET.get("action") or "") == "export_all":
            proxies = [c.to_dict() for c in Pr0cksConfig.objects.all()]
            vms = [v.to_dict() for v in VM.objects.all()]
            bindings = [b.to_dict() for b in RouteBinding.objects.select_related("vm", "pr0cks")]
            payload = {"proxies": proxies, "vms": vms, "bindings": bindings}
            resp = HttpResponse(json.dumps(payload, default=str), content_type="application/json")
            resp["Content-Disposition"] = 'attachment; filename="pr0cks_all_export.json"'
            return resp

        _sync_pids_with_ss()

        bindings_json = [{
            "id": b.id, "vm_id": b.vm_id, "pr0cks_id": b.pr0cks_id, "enabled": b.enabled
        } for b in RouteBinding.objects.all()]

        # ensure bindings are enabled
        for binding in RouteBinding.objects.filter(enabled=True):
            enable_binding(binding)

        # ensure proxies are running
        for proxy in Pr0cksConfig.objects.filter(active=True):
            if not proxy.pid:
                try:
                    pid = _start_pr0cks(proxy.local_proxy, proxy.local_dns, proxy.remote_socks5)
                except Exception as e:
                    return JsonResponse({"error": f"Failed to start pr0cks: {e}"})

        return render(
            request,
            "index.html",
            {
                "configs": Pr0cksConfig.objects.order_by("-updated_at"),
                "vms": VM.objects.order_by("name"),
                "bindings": RouteBinding.objects.select_related("vm", "pr0cks").order_by("vm__name", "pr0cks_id"),
                "bindings_json": json.dumps(bindings_json),
            },
        )

    def post(self, request):
        action = (request.POST.get("action") or "").strip()

        # ----- Proxy -----
        if action == "proxy_add":
            name = (request.POST.get("name") or "").strip()
            local_proxy = (request.POST.get("local_proxy") or "").strip()
            local_dns = (request.POST.get("local_dns") or "").strip()
            remote_socks5 = (request.POST.get("remote_socks5") or "").strip()
            desired_active = (request.POST.get("active", "true").lower() != "false")

            if not all([local_proxy, local_dns, remote_socks5]):
                return JsonResponse({"error": "Missing parameters"})
            if not (is_valid_ip_port(local_proxy) and is_valid_ip_port(local_dns)):
                return JsonResponse({"error": "Invalid local_proxy/local_dns format"})
            if not is_valid_host_port(remote_socks5):
                return JsonResponse({"error": "Invalid remote_socks5 format"})

            pid = None
            if desired_active:
                try:
                    pid = _start_pr0cks(local_proxy, local_dns, remote_socks5)
                except Exception as e:
                    return JsonResponse({"error": f"Failed to start pr0cks: {e}"})

            with transaction.atomic():
                cfg, created = Pr0cksConfig.objects.get_or_create(
                    local_proxy=local_proxy,
                    local_dns=local_dns,
                    defaults={"name": name, "remote_socks5": remote_socks5, "active": desired_active, "pid": pid},
                )
                if not created:
                    cfg.name = name
                    cfg.remote_socks5 = remote_socks5
                    cfg.active = desired_active
                    cfg.pid = pid
                    cfg.save()
            return JsonResponse({"ok": True, "pid": pid})

        if action == "proxy_set_active":
            cfg_id = (request.POST.get("id") or "").strip()
            active = (request.POST.get("active") or "").strip().lower()
            if not cfg_id.isdigit() or active not in {"true", "false"}:
                return JsonResponse({"error": "Missing or invalid id/active"})
            try:
                cfg = Pr0cksConfig.objects.get(id=int(cfg_id))
            except Pr0cksConfig.DoesNotExist:
                return JsonResponse({"error": "Config not found"})

            turning_on = (active == "true")
            if turning_on:
                if not cfg.pid:
                    try:
                        pid = _start_pr0cks(cfg.local_proxy, cfg.local_dns, cfg.remote_socks5)
                        cfg.pid = pid
                    except Exception as e:
                        return JsonResponse({"error": f"Failed to start pr0cks: {e}"})
            else:
                if cfg.pid:
                    _kill_pid(cfg.pid)
                    cfg.pid = None

            cfg.active = turning_on
            cfg.save(update_fields=["active", "pid", "updated_at"])
            return JsonResponse({"ok": True})

        if action == "proxy_delete":
            pid = None
            cfg_id = (request.POST.get("id") or "").strip()
            if not cfg_id.isdigit():
                return JsonResponse({"error": "Missing or invalid id"})
            try:
                cfg = Pr0cksConfig.objects.get(id=int(cfg_id))
            except Pr0cksConfig.DoesNotExist:
                return JsonResponse({"error": "Config not found"})
            for b in RouteBinding.objects.select_related("vm").filter(pr0cks=cfg, enabled=True):
                try:
                    disable_binding(b)
                except Exception:
                    pass
            if cfg.pid:
                pid = cfg.pid
                _kill_pid(cfg.pid)
            cfg.delete()
            return JsonResponse({"ok": True, "killed_pid": pid})

        # ----- VM -----
        if action == "vm_add":
            name = (request.POST.get("name") or "").strip()
            ip = (request.POST.get("ip") or "").strip()
            if not name:
                return JsonResponse({"error": "Missing VM name"})
            vm, created = VM.objects.get_or_create(name=name, defaults={"ip": ip})
            if not created and ip and vm.ip != ip:
                vm.ip = ip
                vm.save(update_fields=["ip", "updated_at"])
            return JsonResponse({"ok": True, "id": vm.id})

        if action == "vm_delete":
            vid = (request.POST.get("id") or "").strip()
            if not vid.isdigit():
                return JsonResponse({"error": "Missing or invalid id"})
            deleted, _ = VM.objects.filter(id=int(vid)).delete()
            return JsonResponse({"ok": bool(deleted)})

        # ----- Binding -----
        if action == "binding_create":
            vm_id = (request.POST.get("vm_id") or "").strip()
            pr_id = (request.POST.get("pr0cks_id") or "").strip()
            if not (vm_id.isdigit() and pr_id.isdigit()):
                return JsonResponse({"error": "Invalid vm_id/pr0cks_id"})
            try:
                vm = VM.objects.get(id=int(vm_id))
                pr = Pr0cksConfig.objects.get(id=int(pr_id))
            except (VM.DoesNotExist, Pr0cksConfig.DoesNotExist):
                return JsonResponse({"error": "VM or Proxy not found"})

            def _extract_port(addr: str) -> Optional[int]:
                m = re.search(r':(\d+)$', addr or "")
                if not m:
                    return None
                p = int(m.group(1))
                return p if 1 <= p <= 65535 else None

            proxy_port = _extract_port(pr.local_proxy)
            dns_port = _extract_port(pr.local_dns)
            if not (proxy_port and dns_port):
                return JsonResponse({"error": "Cannot infer ports from proxy addresses"})

            b, created = RouteBinding.objects.get_or_create(
                vm=vm, pr0cks=pr,
                defaults={"proxy_port": proxy_port, "dns_port": dns_port, "enabled": False}
            )
            if not created:
                changed = False
                if b.proxy_port != proxy_port:
                    b.proxy_port = proxy_port; changed = True
                if b.dns_port != dns_port:
                    b.dns_port = dns_port; changed = True
                if changed:
                    b.save(update_fields=["proxy_port", "dns_port", "updated_at"])
            return JsonResponse({"ok": True, "id": b.id})

        if action == "binding_delete":
            bid = (request.POST.get("binding_id") or "").strip()
            if not bid.isdigit():
                return JsonResponse({"error": "Missing or invalid binding_id"})
            try:
                b = RouteBinding.objects.select_related("vm").get(id=int(bid))
            except RouteBinding.DoesNotExist:
                return JsonResponse({"ok": True})
            try:
                disable_binding(b)
            except Exception:
                pass
            b.delete()
            return JsonResponse({"ok": True})

        if action in {"binding_enable", "binding_disable"}:
            bid = (request.POST.get("binding_id") or "").strip()
            if not bid.isdigit():
                return JsonResponse({"error": "Missing or invalid binding_id"})
            try:
                binding = RouteBinding.objects.select_related("vm", "pr0cks").get(id=int(bid))
            except RouteBinding.DoesNotExist:
                return JsonResponse({"error": "Binding not found"})
            res = enable_binding(binding) if action == "binding_enable" else disable_binding(binding)
            return JsonResponse(res)

        # ----- Import -----
        if action == "import_all":
            try:
                if "file" in request.FILES:
                    payload = json.load(request.FILES["file"])
                else:
                    payload = json.loads((request.body or b"").decode("utf-8"))
                if not isinstance(payload, dict):
                    return HttpResponseBadRequest("JSON must be an object with keys: proxies, vms, bindings")
            except Exception as e:
                return HttpResponseBadRequest(f"Invalid JSON: {e}")

            proxies = payload.get("proxies") or []
            vms = payload.get("vms") or []
            bindings = payload.get("bindings") or []
            if len(proxies) + len(vms) + len(bindings) > MAX_IMPORT_ITEMS:
                return HttpResponseBadRequest("Import too large")

            p_count = v_count = b_count = 0
            errors: List[str] = []

            with transaction.atomic():
                for i, item in enumerate(proxies):
                    try:
                        Pr0cksConfig.from_dict(item); p_count += 1
                    except Exception as e:
                        errors.append(f"proxies[{i}]: {e}")
                for i, item in enumerate(vms):
                    try:
                        VM.from_dict(item); v_count += 1
                    except Exception as e:
                        errors.append(f"vms[{i}]: {e}")
                for i, item in enumerate(bindings):
                    try:
                        RouteBinding.from_dict(item); b_count += 1
                    except Exception as e:
                        errors.append(f"bindings[{i}]: {e}")

            _sync_pids_with_ss()
            return JsonResponse({"proxies": p_count, "vms": v_count, "bindings": b_count, "errors": errors})

        return JsonResponse({"error": "Unknown or disallowed action"})
