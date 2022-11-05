```bash
sudo apt install -y unbound
```

`/etc/unbound/unbound.conf`
```yaml
server:
  do-ip4: yes
  do-ip6: yes
  do-udp: yes

  directory: "/etc/unbound"
  interface: 0.0.0.0@53
  access-control: 0.0.0.0/0 allow
  verbosity: 3

  local-zone: "internal." static
    local-data: "api.internal IN A 10.64.10.1"
    local-data: "dns.internal IN A 10.64.10.2"
    local-data: "ca.internal IN A 10.64.10.3"
    local-data: "keyserver.internal IN A 10.64.10.3"
    local-data: "admin.internal IN A 10.64.10.4"
    local-data: "attacker.internal IN A 10.64.10.4"
```

```bash
student@dns:~$ sudo systemctl disable --now systemd-resolved
Removed /etc/systemd/system/dbus-org.freedesktop.resolve1.service.
Removed /etc/systemd/system/multi-user.target.wants/systemd-resolved.service.
student@dns:~$ sudo systemctl enable --now unbound
Synchronizing state of unbound.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable unbound
```

VMs:
1. API
2. DNS
3. CA and keyserver
4. Attacker/client/admin

### Setup keyserver VLAN between CA and API

CA:
sudo ip link add link ens3 name ens3.10 type vlan id 10
sudo ip addr add dev ens3.10 172.16.10.1/24
sudo ip link set dev ens3.10 up

API:
sudo ip link add link ens3 name ens3.10 type vlan id 10
sudo ip addr add dev ens3.10 172.16.10.2/24
sudo ip link set dev ens3.10 up

## Compromise communication channel between API and keyserver

Notice keyserver.internal, resolve to 172.16.10.2 and assume vlan 10

(Mitigation: remove internal IPs in public DNS. Also enable DNS rebinding protection to prohibit RFC1918 addresses in resolver answers)

```bash
student@client:~$ sudo tcpdump -i ens3 -n -e vlan
```
