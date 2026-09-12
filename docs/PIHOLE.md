# Pi-hole on Castle OS (x86_64 — no Raspberry Pi needed)

Yes. Pi-hole is just software; the "Pi" in the name is history. It runs on
any 64-bit Linux, including the old Lenovo (or any x86_64 Castle box).

One caveat: Pi-hole's official install script does **not** support
Arch Linux, and Castle OS is Arch-based. So on Castle OS, Pi-hole runs as a
Docker container — which is also the cleaner appliance story (one compose
file per service, no host pollution). The CLI profile ships `docker` and
starts `docker.service` on boot for exactly this.

## Run it

```bash
# 1. Give the Castle a static LAN IP first (example: 192.168.1.10).
#    Do this on your router's DHCP reservation page — simplest and survives reboots.

# 2. Start Pi-hole:
docker run -d \
  --name pihole \
  --restart unless-stopped \
  -p 53:53/tcp -p 53:53/udp \
  -p 80:80/tcp \
  -e TZ=America/Chicago \
  -e WEBPASSWORD='pick-a-strong-password' \
  -v pihole-etc:/etc/pihole \
  -v pihole-dnsmasq:/etc/dnsmasq.d \
  pihole/pihole:latest

# 3. Open http://192.168.1.10/admin and log in with WEBPASSWORD.

# 4. Point your router's DHCP DNS at 192.168.1.10 (or set DNS per device).
#    Every device on the LAN now ad-blocks with zero per-device setup.
```

## Notes

- The live USB runs this fine, but container volumes live in RAM on the
  live medium — for a permanent Pi-hole, install to disk first
  (`castle-install`), then run the container there.
- Port 53 must be free on the host: the CLI profile ships `dnsmasq` but
  does not start it, so there is no conflict out of the box. If you later
  enable dnsmasq as the LAN DHCP server, keep DNS on Pi-hole and DHCP on
  dnsmasq, or let Pi-hole do DHCP instead — not both on port 53.
- Upstream DNS for Pi-hole itself defaults to Cloudflare/Google; change it
  in the web UI under Settings → DNS if you want something else.
- Unbound (recursive DNS, no upstream) is the usual next step once the
  basic setup proves itself — one more container, same pattern.
