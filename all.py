from scapy.arch.linux import enable_nonroot_backend

# Apply fallback if not root
if enable_nonroot_backend:
    enable_nonroot_backend()
