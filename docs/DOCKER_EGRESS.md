# Docker outbound network troubleshooting

NekoRoute downloads public proxy metadata over HTTPS. If every source reports a timeout, the problem is usually Docker bridge egress/NAT rather than the source parser.

## 1. Check the host

```bash
curl -4 -I --connect-timeout 8 \
  https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json
```

If this times out on the host too, fix the host/VPS firewall or upstream network first.

## 2. Check inside NekoRoute

```bash
docker exec nekoroute node -e '
const dns=require("node:dns");
const https=require("node:https");
dns.lookup("raw.githubusercontent.com",{family:4},(e,a)=>console.log("DNS:",e?.code||a));
const r=https.get("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json",{family:4},res=>{console.log("HTTPS:",res.statusCode);res.destroy();});
r.setTimeout(8000,()=>{console.error("HTTPS: TIMEOUT");r.destroy();});
r.on("error",e=>console.error("HTTPS:",e.code,e.message));
'
```

If DNS resolves but HTTPS times out, Docker forwarding/NAT is being dropped.

## 3. Check Docker forwarding/NAT

```bash
sysctl net.ipv4.ip_forward
sudo iptables -L FORWARD -n -v
sudo iptables -L DOCKER-USER -n -v --line-numbers
sudo iptables -t nat -S POSTROUTING | grep -E 'MASQUERADE|docker' || true
sudo cat /etc/docker/daemon.json 2>/dev/null || true
sudo systemctl cat docker | grep -E -- '--iptables|--ip-forward|--ip-masq' || true
```

Docker bridge networking normally requires IPv4 forwarding, Docker firewall rules and masquerading. In normal installations these settings should not be disabled.

If `/etc/docker/daemon.json` or the Docker systemd command line contains any of these, remove/fix them unless you intentionally manage all Docker networking yourself:

```json
{
  "iptables": false,
  "ip-forward": false,
  "ip-masq": false
}
```

The normal values are `true`.

To enable IPv4 forwarding immediately and persist it:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
printf 'net.ipv4.ip_forward=1\n' | sudo tee /etc/sysctl.d/99-docker-ip-forward.conf
sudo sysctl --system
```

After correcting Docker daemon settings:

```bash
sudo systemctl restart docker
docker compose up -d
```

Do not flush Docker's iptables/nftables chains.

## 4. Fast Linux workaround: host networking

If HTTPS works on the host but not in the normal NekoRoute container, use the included host-network compose file:

```bash
docker compose down
docker compose -f docker-compose.host-network.yml up -d --build
docker compose -f docker-compose.host-network.yml logs -f nekoroute
```

NekoRoute will bind directly to host port `3210`. There is no `ports:` mapping in this mode because the container uses the host network namespace.

Return to normal bridge networking later with:

```bash
docker compose -f docker-compose.host-network.yml down
docker compose up -d --build
```

## 5. UFW / custom firewall rules

If `DOCKER-USER` contains a blanket DROP/REJECT rule before Docker traffic is accepted, it can black-hole outbound container connections. Inspect the rule counters before changing anything:

```bash
sudo iptables -L DOCKER-USER -n -v --line-numbers
```

Do not blindly flush this chain. If custom firewall policy is required, add a narrowly scoped allow rule for the NekoRoute bridge/subnet and established return traffic, then persist it using the firewall manager used by the host.
