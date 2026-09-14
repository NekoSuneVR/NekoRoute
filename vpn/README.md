# Trusted VPN sidecar profiles

Put only VPN profiles you trust in this directory and keep private keys/configs out of Git.

The provided compose example expects `vpn/wg0.conf`, which is ignored by `.gitignore`.
For OpenVPN, use Gluetun's custom-provider OpenVPN settings instead of the WireGuard settings shown in the example.
