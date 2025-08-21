from __future__ import annotations

from typing import Any, Dict, Optional

from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.db import models

from django.db.models.signals import pre_delete
from django.dispatch import receiver

# --- Validators ---
IP_PORT_RE = r'(?:\[(?:[0-9A-Fa-f:]+)\]|(?:\d{1,3}(?:\.\d{1,3}){3})):(?:\d{1,5})'
HOST_PORT_RE = r'(?:[A-Za-z0-9.-]+|\[(?:[0-9A-Fa-f:]+)\]):(?:\d{1,5})'

ip_port_validator = RegexValidator(
    regex=rf'^{IP_PORT_RE}$',
    message='Use IP:port (IPv4 a.b.c.d:port or [IPv6]:port).',
)

host_port_validator = RegexValidator(
    regex=rf'^{HOST_PORT_RE}$',
    message='Use host/ip:port (e.g. socks.example.com:1080 or 1.2.3.4:1080 or [::1]:1080).',
)


# --- Models ---
class Pr0cksConfig(models.Model):
    name = models.CharField(max_length=64)  # es. clearnet, vpn, tor
    local_proxy = models.CharField(unique=True, max_length=64, validators=[ip_port_validator])
    local_dns = models.CharField(unique=True, max_length=64, validators=[ip_port_validator])
    remote_socks5 = models.CharField(max_length=128, validators=[host_port_validator])
    active = models.BooleanField(default=True)
    pid = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["local_proxy"]),
            models.Index(fields=["local_dns"]),
            models.Index(fields=["pid"]),
            models.Index(fields=["active"]),
            models.Index(fields=["updated_at"]),
        ]
        ordering = ["-updated_at"]

    def __str__(self) -> str:
        label = f"[{self.name}] " if self.name else ""
        return f"{label}{self.local_proxy} / {self.local_dns} -> {self.remote_socks5}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "local_proxy": self.local_proxy,
            "local_dns": self.local_dns,
            "remote_socks5": self.remote_socks5,
            "active": self.active,
            "pid": self.pid,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Pr0cksConfig":
        lp = (data.get("local_proxy") or "").strip()
        if not lp:
            raise ValueError("Local proxy is required")
        ld = (data.get("local_dns") or "").strip()
        if not ld:
            raise ValueError("Local DNS is required")
        rs = (data.get("remote_socks5") or "").strip()
        if not rs:
            raise ValueError("Remote socks5 is required")
        nm = (data.get("name") or "").strip()
        if not nm:
            raise ValueError("Name is required")
        active = bool(data.get("active", True))
        obj, created = cls.objects.get_or_create(
            local_proxy=lp,
            local_dns=ld,
            defaults={"remote_socks5": rs, "name": nm, "active": active},
        )
        if not created:
            changed = False
            if nm != obj.name:
                obj.name = nm; changed = True
            if rs and obj.remote_socks5 != rs:
                obj.remote_socks5 = rs; changed = True
            if obj.active != active:
                obj.active = active; changed = True
            if changed:
                obj.save(update_fields=["name", "remote_socks5", "active", "updated_at"])
        return obj

class VM(models.Model):
    name = models.CharField(max_length=128, unique=True)
    ip = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["ip"]),
            models.Index(fields=["updated_at"]),
        ]
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.ip or 'no-ip'})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VM":
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("VM name is required")
        ip = (data.get("ip") or "").strip()
        if not ip:
            raise ValueError("IP address is required")
        obj, created = cls.objects.get_or_create(
            name=name,
            defaults={"ip": ip},
        )
        if not created:
            changed = False
            if obj.ip != ip:
                obj.ip = ip; changed = True
            if changed:
                obj.save(update_fields=["ip", "updated_at"])
        return obj

class RouteBinding(models.Model):
    vm = models.ForeignKey(VM, on_delete=models.CASCADE)
    pr0cks = models.ForeignKey(Pr0cksConfig, on_delete=models.CASCADE)
    proxy_port = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)])
    dns_port = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)])
    enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["vm", "pr0cks"], name="uniq_vm_proxy")]
        indexes = [
            models.Index(fields=["vm"]),
            models.Index(fields=["pr0cks"]),
            models.Index(fields=["enabled"]),
            models.Index(fields=["updated_at"]),
        ]
        ordering = ["vm__name", "pr0cks_id"]

    def __str__(self) -> str:
        return f"{self.vm.name} -> proxy:{self.proxy_port} dns:{self.dns_port} (enabled={self.enabled})"

    def tag(self) -> str:
        return f"pr0cks_vm:{self.id}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vm_id": self.vm_id,
            "vm_name": self.vm.name if self.vm_id else None,
            "pr0cks_id": self.pr0cks_id,
            "pr0cks_local_proxy": self.pr0cks.local_proxy if self.pr0cks_id else None,
            "pr0cks_local_dns": self.pr0cks.local_dns if self.pr0cks_id else None,
            "proxy_port": self.proxy_port,
            "dns_port": self.dns_port,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RouteBinding":
        vm_obj: Optional[VM] = None
        if data.get("vm_id"):
            vm_obj = VM.objects.get(id=int(data["vm_id"]))
        elif data.get("vm_name"):
            vm_obj = VM.objects.get(name=data["vm_name"])
        else:
            raise ValueError("Binding requires vm_id or vm_name")

        pr_obj: Optional[Pr0cksConfig] = None
        if data.get("pr0cks_id"):
            pr_obj = Pr0cksConfig.objects.get(id=int(data["pr0cks_id"]))
        elif data.get("pr0cks_local_proxy") and data.get("pr0cks_local_dns"):
            pr_obj = Pr0cksConfig.objects.get(
                local_proxy=data["pr0cks_local_proxy"], local_dns=data["pr0cks_local_dns"]
            )
        else:
            raise ValueError("Binding requires pr0cks_id or (pr0cks_local_proxy, pr0cks_local_dns)")

        proxy_port = int(data.get("proxy_port"))
        dns_port = int(data.get("dns_port"))
        enabled = bool(data.get("enabled", "False"))

        obj, created = cls.objects.get_or_create(
            vm=vm_obj, pr0cks=pr_obj,
            defaults={"proxy_port": proxy_port, "dns_port": dns_port, "enabled": enabled},
        )
        if not created:
            changed = False
            if obj.proxy_port != proxy_port:
                obj.proxy_port = proxy_port; changed = True
            if obj.dns_port != dns_port:
                obj.dns_port = dns_port; changed = True
            if obj.enabled != enabled:
                obj.enabled = enabled; changed = True
            if changed:
                obj.save(update_fields=["proxy_port", "dns_port", "enabled", "updated_at"])
        return obj


# --- on_delete Signals handlers ---
@receiver(pre_delete, sender=RouteBinding)
def cleanup_binding_rules_on_delete(sender, instance: RouteBinding, **kwargs):
    try:
        from .views import disable_binding
        if instance.enabled:
            disable_binding(instance)
    except Exception:
        pass


@receiver(pre_delete, sender=Pr0cksConfig)
def cleanup_proxy_on_delete(sender, instance: Pr0cksConfig, **kwargs):
    try:
        from .views import _kill_pid
        if instance.pid:
            _kill_pid(instance.pid)
    except Exception:
        pass
