# QubesOS
In this repository, I'll collect all the scripts I use for my personal distro, which runs on multiple VMs. The idea is to achieve nearly the same level of security as QubesOS, but using only isolation between VMs and iptables for traffic proxying.

## send_passwd_to_encrypted_vm.sh

Normally, when the VM’s operating system is running, spice-vdagent intercepts keyboard shortcuts and allows you to paste text (for example, using `CTRL+SHIFT+V`). The problem arises when the disk is encrypted: at this stage, the operating system hasn’t booted yet, so `spice-vdagent` isn’t active and there’s no channel for direct pasting.

To work around this limitation, I created a small script that takes the VM name as the first parameter and a string as the second. The script sends the string character by character to the VM using `virsh send-key`. After a few seconds, the password is automatically typed in, and at the end, the script also presses the `Enter` key.
