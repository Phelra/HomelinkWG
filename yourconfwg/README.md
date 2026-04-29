# WireGuard Configuration

Place your WireGuard client config here as `wg0.conf`.

## Example

```ini
[Interface]
PrivateKey = YOUR_PRIVATE_KEY_HERE
Address = 10.8.0.X/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = SERVER_PUBLIC_KEY
PresharedKey = OPTIONAL_PRESHARED_KEY
Endpoint = your.vpn.server.com:51820
AllowedIPs = 10.8.0.0/24, 192.168.X.0/24
PersistentKeepalive = 25
```

## Notes

- `AllowedIPs` defines the subnets routed through the VPN. Make sure they match
  the remote network you want to reach (e.g. `192.168.60.0/24` for your LAN).
- This file must NEVER be committed to a public Git repo (it contains the
  private key). It is already excluded by `.gitignore`.
- The container mounts this file read-only at `/etc/wireguard/wg0.conf`.
