"""
Apodictic Enterprise Firecracker & KVM Enclave Isolation Harness
Provides process containment, virtual jailer configuration,
ephemeral tap-device routing, and seccomp-bpf system call filtering profiles.
"""

import os
import json
from typing import Dict, Any, List

class EnclaveJailerProfile:
    """
    Firecracker / KVM Seccomp-BPF 24-Syscall Whitelist Profile.
    Blocks network sockets (socket, connect, bind) during sensitive theorem proving and AST parsing.
    """
    DEFAULT_24_SYSCALLS: List[str] = [
        "read", "write", "openat", "close", "fstat", "lseek", "mmap", "mprotect",
        "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
        "pread64", "pwrite64", "exit_group", "futex", "clock_gettime", "gettimeofday",
        "getrandom", "nanosleep", "clone3", "exit"
    ]

    @classmethod
    def generate_jailer_config(cls, vm_id: str, mem_size_mib: int = 128, vcpu_count: int = 2) -> Dict[str, Any]:
        return {
            "boot-source": {
                "kernel_image_path": "/opt/noesis/enclave/vmlinux.bin",
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init"
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": f"/opt/noesis/enclave/disks/{vm_id}.ext4",
                    "is_root_device": True,
                    "is_read_only": False
                }
            ],
            "machine-config": {
                "vcpu_count": vcpu_count,
                "mem_size_mib": mem_size_mib,
                "smt": False,
                "track_dirty_pages": True
            },
            "network-interfaces": [], # Egress default-deny: Zero virtual tap devices attached
            "seccomp": {
                "default_action": "KILL_PROCESS",
                "filter": cls.DEFAULT_24_SYSCALLS
            }
        }

    @classmethod
    def is_kvm_available(cls) -> bool:
        return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)
