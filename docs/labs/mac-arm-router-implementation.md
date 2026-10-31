# Apple Silicon Mac — ARM64 Ubuntu router implementation

<badge color="warning">Reference configuration — validate from VM console before relying on it</badge>

This is the Mac-only routing/firewall implementation for Apple Silicon. It uses an ARM64 Ubuntu Server guest with Netplan, nftables and optional dnsmasq. It is **not OPNsense** and does not provide its GUI/plugins. OPNsense is x86-64; do not install its x86-64 image as a native ARM64 guest.

## 1. Prerequisites and safety

- Apple Silicon Mac and a supported VMware Fusion release.
- Ubuntu Server ARM64 image verified from the official Ubuntu source.
- One Fusion NAT network for WAN and distinct isolated networks for MGMT, ENDPOINT, SERVER, REDTEAM and DMZ.
- A VM console path. Do not perform first firewall/network changes over the only SSH session.
- A written interface-to-network-to-MAC inventory and a clean VM snapshot.

Fusion NAT is only the upstream virtual network; it is not the lab's security policy. Never attach REDTEAM or DMZ directly to Bridged networking. Fusion NAT, host-only and bridged networks do not automatically mirror packets.

## 2. Create the VM and adapters

Create VM PSV-MAC-RTR01 with ARM64 Ubuntu Server, 2–4 vCPU, 4–8 GB RAM and at least 40 GB disk. Add:
1. WAN — Fusion NAT.
2. MGMT — dedicated private network.
3. ENDPOINT — dedicated private network.
4. SERVER — dedicated private network.
5. REDTEAM — dedicated private network.
6. DMZ — dedicated private network.
7. SENSOR-MGMT — optional, dedicated private network for sensor administration only.

The exact number and naming of custom networks depend on the Fusion release. If the installed Fusion version cannot provide separate isolated networks, stop and redesign; do not collapse them into one host-only segment.

Boot Ubuntu, set the guest hostname, and confirm ARM64:

~~~bash
sudo hostnamectl set-hostname PSV-MAC-RTR01
hostnamectl
~~~

Use this exact hostname in the relay's source-identification rule. The SERVER interface in this example is 10.10.30.1/24.

~~~bash
uname -m
ip -br link
ip -br address
ip route
~~~

Expected architecture: aarch64. Record every adapter MAC and map it to its Fusion network. Never assume Linux interface enumeration matches the order displayed in Fusion.

## 3. Netplan — stable interface names by MAC

Create /etc/netplan/60-psv-router.yaml. Replace every placeholder with the real lowercase MAC address. Remove the SENSOR-MGMT stanza if that adapter is not present.

~~~yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    wan0:
      match:
        macaddress: "REPLACE-WAN-MAC"
      set-name: wan0
      dhcp4: true
      dhcp6: false
      accept-ra: false
    mgmt0:
      match:
        macaddress: "REPLACE-MGMT-MAC"
      set-name: mgmt0
      dhcp4: false
      dhcp6: false
      addresses: [10.10.10.1/24]
    endpoint0:
      match:
        macaddress: "REPLACE-ENDPOINT-MAC"
      set-name: endpoint0
      dhcp4: false
      dhcp6: false
      addresses: [10.10.20.1/24]
    server0:
      match:
        macaddress: "REPLACE-SERVER-MAC"
      set-name: server0
      dhcp4: false
      dhcp6: false
      addresses: [10.10.30.1/24]
    redteam0:
      match:
        macaddress: "REPLACE-REDTEAM-MAC"
      set-name: redteam0
      dhcp4: false
      dhcp6: false
      addresses: [10.10.40.1/24]
    dmz0:
      match:
        macaddress: "REPLACE-DMZ-MAC"
      set-name: dmz0
      dhcp4: false
      dhcp6: false
      addresses: [10.10.60.1/24]
    sensormgmt0:
      match:
        macaddress: "REPLACE-SENSOR-MGMT-MAC"
      set-name: sensormgmt0
      dhcp4: false
      dhcp6: false
      addresses: [10.10.50.1/24]
~~~

If WAN is static, replace DHCP with the actual Fusion NAT address, prefix and DNS learned from that virtual network. Do not guess gateway values. Validate and apply from the VM console:

~~~bash
sudo netplan generate
sudo netplan try
# Confirm only after checking interface names and connectivity.
sudo netplan apply
ip -br address
ip route
networkctl status wan0
~~~

There must be exactly one default route through WAN. Internal interfaces must not have default gateways. If connectivity is lost, use the console and restore the last known-good YAML or snapshot.

## 4. IPv4 forwarding and IPv6 policy

This reference profile is IPv4-only. IPv6 must not provide an unfiltered alternate route. If IPv6 is required, design equivalent IPv6 input/forward rules, router advertisements, DNS and logging before enabling it.

Create /etc/sysctl.d/60-psv-router.conf:

~~~ini
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.forwarding=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
~~~

Apply and verify:

~~~bash
sudo sysctl --system
sysctl net.ipv4.ip_forward
sysctl net.ipv6.conf.all.disable_ipv6
~~~

Expected IPv4 forwarding is 1 and IPv6 disable is 1 for this profile.

## 5. nftables baseline

Install packages:

~~~bash
sudo apt update
sudo apt install -y nftables rsyslog tcpdump
sudo systemctl enable --now nftables
~~~

Create /etc/nftables.conf on this dedicated router VM only. The first line flushes the entire nftables ruleset; do not use this file on a general-purpose Ubuntu host, a Docker host or a system with other firewall owners. Replace the admin IP and DMZ target with real static addresses. The example only permits REDTEAM to the named DMZ target on sample TCP ports 80/443/8080. Change ports to the exact target services. Add narrowly scoped AD, DNS, SIEM and telemetry rules only after identifying exact source, destination and port. Do not open entire subnets to any service.

~~~nft
#!/usr/sbin/nft -f
flush ruleset

define wan_if = "wan0"
define mgmt_admin = 10.10.10.10
define dmz_target = 10.10.60.20

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "mgmt0" ip saddr $mgmt_admin tcp dport 22 ct state new accept
    iifname "mgmt0" ip saddr 10.10.10.0/24 ip protocol icmp limit rate 5/second accept

    # Uncomment only when dnsmasq is enabled. DHCP is offered on MGMT, ENDPOINT, REDTEAM and DMZ only; SERVER is static/reservation-only.
    # iifname { "mgmt0", "endpoint0", "redteam0", "dmz0" } udp dport 67 accept
    # iifname { "mgmt0", "endpoint0", "server0", "sensormgmt0", "redteam0", "dmz0" } udp dport 53 accept
    # iifname { "mgmt0", "endpoint0", "server0", "sensormgmt0", "redteam0", "dmz0" } tcp dport 53 accept

    limit rate 5/second log prefix "PSV-ROUTER-INPUT-DROP " flags all counter
    counter drop
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept

    iifname "redteam0" oifname "dmz0" ip daddr $dmz_target tcp dport { 80, 443, 8080 } ct state new accept

    # Sensor management: permit the named MGMT admin host to reach sensor management services only.
    # iifname "mgmt0" oifname "sensormgmt0" ip saddr $mgmt_admin ip daddr 10.10.50.0/24 tcp dport { 22, 443 } ct state new accept

    # Optional AD DS flows — uncomment only if a lab DC exists at 10.10.30.10.
    # iifname "endpoint0" oifname "server0" ip daddr 10.10.30.10 udp dport { 53, 88, 389, 464 } ct state new accept
    # iifname "endpoint0" oifname "server0" ip daddr 10.10.30.10 tcp dport { 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 9389 } ct state new accept
    # iifname "endpoint0" oifname "server0" ip daddr 10.10.30.10 tcp dport 49152-65535 ct state new accept
    # If the sensor management host uses AD DNS/NTP, allow only these services to the DC:
    # iifname "sensormgmt0" ip saddr 10.10.50.10 oifname "server0" ip daddr 10.10.30.10 udp dport { 53, 123 } ct state new accept
    # iifname "sensormgmt0" ip saddr 10.10.50.10 oifname "server0" ip daddr 10.10.30.10 tcp dport 53 ct state new accept

    # Select ONE SIEM path and replace the sample manager IP/ports with the actual deployment.
    # Wazuh agent secure channel + enrollment (Wazuh manager example 10.10.30.22).
    # iifname "endpoint0" oifname "server0" ip daddr 10.10.30.22 tcp dport { 1514, 1515 } ct state new accept
    # Elastic Agent to Fleet Server/Elasticsearch (Elastic example 10.10.30.20; split destinations if separate).
    # iifname "endpoint0" oifname "server0" ip daddr 10.10.30.20 tcp dport { 8220, 9200 } ct state new accept
    # Splunk Universal Forwarder to receiver (Splunk example 10.10.30.21).
    # iifname "endpoint0" oifname "server0" ip daddr 10.10.30.21 tcp dport 9997 ct state new accept
    # Management UI access from the named admin host only; uncomment only the selected product rule.
    # Elastic Kibana:
    # iifname "mgmt0" ip saddr $mgmt_admin oifname "server0" ip daddr 10.10.30.20 tcp dport 5601 ct state new accept
    # Splunk Web:
    # iifname "mgmt0" ip saddr $mgmt_admin oifname "server0" ip daddr 10.10.30.21 tcp dport 8000 ct state new accept
    # Wazuh Dashboard:
    # iifname "mgmt0" ip saddr $mgmt_admin oifname "server0" ip daddr 10.10.30.22 tcp dport 443 ct state new accept
    # Sensor management agent to the selected SIEM; capture-only NICs have no IP and are not routed.
    # Wazuh sensor agent:
    # iifname "sensormgmt0" oifname "server0" ip daddr 10.10.30.22 tcp dport 1514 ct state new accept
    # Elastic sensor agent:
    # iifname "sensormgmt0" oifname "server0" ip daddr 10.10.30.20 tcp dport { 8220, 9200 } ct state new accept
    # Splunk sensor forwarder:
    # iifname "sensormgmt0" oifname "server0" ip daddr 10.10.30.21 tcp dport 9997 ct state new accept

    # Optional temporary update egress for trusted lab segments only. Remove after patching.
    iifname { "mgmt0", "endpoint0", "server0" } oifname $wan_if ip saddr { 10.10.10.0/24, 10.10.20.0/24, 10.10.30.0/24 } tcp dport { 80, 443 } ct state new accept
    iifname { "mgmt0", "endpoint0", "server0" } oifname $wan_if ip saddr { 10.10.10.0/24, 10.10.20.0/24, 10.10.30.0/24 } udp dport { 53, 123 } ct state new accept
    iifname { "mgmt0", "endpoint0", "server0" } oifname $wan_if ip saddr { 10.10.10.0/24, 10.10.20.0/24, 10.10.30.0/24 } tcp dport 53 ct state new accept
    # Optional sensor OS/package updates: sensor management host only (10.10.50.10). Remove after maintenance.
    iifname "sensormgmt0" oifname $wan_if ip saddr 10.10.50.10 tcp dport { 80, 443 } ct state new accept
    iifname "sensormgmt0" oifname $wan_if ip saddr 10.10.50.10 udp dport 123 ct state new accept

    limit rate 5/second log prefix "PSV-ROUTER-FWD-DROP " flags all counter
    counter drop
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "wan0" ip saddr { 10.10.10.0/24, 10.10.20.0/24, 10.10.30.0/24, 10.10.50.10/32 } masquerade
  }
}
~~~

This is a restrictive learning baseline, not a universal enterprise policy. Router-originated output is permissive in this sample; harden it for your chosen services. The optional update-egress rules permit only web, DNS and NTP from trusted segments. Remove them for a fully offline lab. There is deliberately no DMZ-to-trusted, REDTEAM-to-trusted or SENSOR-MGMT-to-client forwarding rule. The only optional SENSOR-MGMT egress is the single sensor host's temporary package-update rule.

Syntax-check before applying:

~~~bash
sudo nft -c -f /etc/nftables.conf
sudo nft -f /etc/nftables.conf
sudo nft list ruleset
sudo systemctl enable nftables
sudo systemctl status nftables --no-pager
~~~

Keep the VM console open. Confirm router SSH works from the named MGMT admin host and is denied from ENDPOINT, REDTEAM and DMZ. Do not assume a failed ping proves a firewall rule.

## 6. DHCP and DNS — only after static routing works

Start with static addresses. Do not run Fusion DHCP and dnsmasq DHCP on the same internal L2 segment.

If dnsmasq is selected, install it and create /etc/dnsmasq.d/psv-lab.conf. This sample explicitly tags DHCP scopes by the receiving interface. The standalone DNS options point clients at the router's interface address; replace the ENDPOINT DNS option with the AD DNS address when domain services are deployed:

~~~ini
interface=mgmt0
interface=endpoint0
interface=server0
interface=sensormgmt0
interface=redteam0
interface=dmz0
bind-interfaces
# On Ubuntu with systemd-resolved, use the upstream resolver list rather than the local stub file.
resolv-file=/run/systemd/resolve/resolv.conf

dhcp-range=tag:mgmt0,10.10.10.100,10.10.10.150,255.255.255.0,12h
dhcp-option=tag:mgmt0,option:router,10.10.10.1
dhcp-option=tag:mgmt0,option:dns-server,10.10.10.1
dhcp-range=tag:endpoint0,10.10.20.100,10.10.20.199,255.255.255.0,12h
dhcp-option=tag:endpoint0,option:router,10.10.20.1
# Standalone endpoint DNS; if AD DS/DNS is deployed, replace 10.10.20.1 with 10.10.30.10.
dhcp-option=tag:endpoint0,option:dns-server,10.10.20.1
dhcp-range=tag:redteam0,10.10.40.100,10.10.40.150,255.255.255.0,12h
dhcp-option=tag:redteam0,option:router,10.10.40.1
dhcp-option=tag:redteam0,option:dns-server,10.10.40.1
dhcp-range=tag:dmz0,10.10.60.100,10.10.60.150,255.255.255.0,12h
dhcp-option=tag:dmz0,option:router,10.10.60.1
# Explicitly advertise the router as DNS for a standalone, non-domain DMZ.
dhcp-option=tag:dmz0,option:dns-server,10.10.60.1
~~~

By default, dnsmasq offers its own interface address as the DNS server and forwards queries using its upstream resolver list. The resolv-file line above points at Ubuntu systemd-resolved's upstream list; verify that file exists and contains the intended upstream servers. The SERVER and SENSOR-MGMT subnets remain static/reservation-only: do not create DHCP scopes there. The sensor management host example is 10.10.50.10/24 with gateway/DNS 10.10.50.1; capture NICs have no address, gateway or DHCP. If AD DS is deployed, explicitly set DHCP option 6 for domain-member scopes to the DC DNS address (10.10.30.10), and configure the DC to forward non-domain queries as designed. Do not advertise dnsmasq/public DNS to domain members. The optional sensor update rules permit only 10.10.50.10 to HTTP/HTTPS and NTP; remove them after maintenance.

Validate:

~~~bash
sudo dnsmasq --test
sudo systemctl enable --now dnsmasq
sudo systemctl status dnsmasq --no-pager
sudo journalctl -u dnsmasq -n 100 --no-pager
sudo ss -lunp | grep -E ':(53|67)( |$)'
~~~

On a Linux DHCP client, renew the lease using the network manager/client appropriate to that guest, then verify:

~~~bash
ip -4 address
ip route
resolvectl status
dig @10.10.20.1 example.com
~~~

Replace 10.10.20.1 with that guest's segment DNS address. For a Windows guest use `ipconfig /release`, `ipconfig /renew`, `ipconfig /all`, and `nslookup example.com 10.10.20.1`. In an AD domain, query the DC DNS directly for the domain controller SRV record and confirm the expected DC is returned. A DHCP lease alone does not prove DNS is correct.

## 7. Local firewall logs and relay forwarding

The nftables rules emit kernel log messages with unique prefixes. Confirm them:

~~~bash
sudo journalctl -k -g 'PSV-ROUTER-' --since '10 minutes ago'
~~~

Create /etc/rsyslog.d/30-psv-router-local.conf. Keep local writing before forwarding, and do not stop processing here:

~~~text
:msg, contains, "PSV-ROUTER-" /var/log/psv-router-firewall.log
~~~

Validate and restart:

~~~bash
sudo rsyslogd -N1
sudo systemctl restart rsyslog
~~~

Generate a known blocked flow and verify the record in /var/log/psv-router-firewall.log.

Ubuntu normally configures rsyslog to read the system journal and/or kernel log. Confirm the installed configuration has a working journal/kernel input; do not load a duplicate input module if it is already enabled:

~~~bash
grep -R -E 'module\(load="(imjournal|imklog)"' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
~~~

 
If neither journal nor kernel input is enabled, add the following once (do not duplicate an existing module) to /etc/rsyslog.d/05-psv-journal-input.conf:

~~~text
module(load="imjournal" StateFile="imjournal.state")
~~~

Validate the complete configuration with rsyslogd -N1 and confirm a test kernel log record is received before proceeding.

Create /etc/rsyslog.d/40-psv-router-forward.conf to forward only the tagged nftables records to the SERVER relay. The later filename ensures the local file action above runs first. The relay must already allow this router's SERVER-facing source address and hostname. Replace the relay IP/port if your deployment differs:

~~~text
if ($msg contains "PSV-ROUTER-") then {
    action(
        type="omfwd"
        target="10.10.30.30"
        port="514"
        protocol="tcp"
        template="RSYSLOG_SyslogProtocol23Format"
        queue.type="LinkedList"
        queue.filename="psv-router-fwd"
        queue.maxDiskSpace="1g"
        queue.saveOnShutdown="on"
        action.resumeRetryCount="-1"
    )
    stop
}
~~~

Validate and restart:

~~~bash
sudo rsyslogd -N1
sudo systemctl restart rsyslog
sudo systemctl status rsyslog --no-pager
~~~

Generate a blocked test flow, confirm the unique PSV-ROUTER prefix in the local file, then on PSV-LOG01 run `sudo grep 'PSV-ROUTER-' /var/log/remote/psv-mac-router.log` and confirm the same message arrives with the PSV-MAC-RTR01 identity. Confirm the forwarding queue remains bounded and monitor rsyslog errors. TCP/514 is permitted only on the isolated lab segment; use the TLS configuration in the relay guide on shared or untrusted paths.

Create /etc/logrotate.d/psv-router:

~~~text
/var/log/psv-router-firewall.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
~~~

Dry-run and verify the actual file path/owner:

~~~bash
sudo logrotate -d /etc/logrotate.d/psv-router
sudo ls -l /var/log/psv-router-firewall.log
df -h /var/log
~~~

Configure logrotate with bounded retention and correct permissions before forwarding or collecting this file. Do not configure SIEM agents at this stage.

## 8. Acceptance tests

From each guest, record Windows ipconfig /all or Linux ip -br address and ip route. Verify:
- Each guest reaches its own router gateway.
- DNS/NTP use the intended lab services.
- REDTEAM reaches only the approved DMZ target and declared ports.
- DMZ cannot initiate to MGMT, ENDPOINT, SERVER or home LAN.
- ENDPOINT cannot access router management ports.
- Router SSH is reachable only from the named MGMT admin host.
- IPv6 is not an unfiltered alternate route.
- nftables counters and logs reflect allowed and denied tests.
- After reboot, Netplan, forwarding, nftables and optional DHCP/DNS persist.

Use TCP/UDP tests for real services and inspect counters/logs. Ping alone is insufficient.

## 9. Fusion packet-visibility limitation

This router does not create a SPAN feed. Capture on router interfaces with tcpdump for routed-boundary traffic, or use an external managed-switch SPAN/TAP. Traffic switched locally between guests on the same Fusion virtual network may never traverse the router and will not appear on router interfaces. Offline PCAP is valid for deterministic analysis but must be labelled offline, not live monitoring.

## 10. Recovery procedure

Before each change: snapshot the VM, keep console access, save current Netplan/nftables files, run validation commands, change one subsystem at a time, and re-run all acceptance tests after recovery. If access is lost, restore from console or revert the snapshot.

## References

- [Ubuntu Server networking documentation](https://ubuntu.com/server/docs)
- [Netplan documentation](https://netplan.readthedocs.io/)
- [nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
- [dnsmasq manual — DHCP ranges, interface tags and options](https://dnsmasq.org/docs/dnsmasq-man.html)
- [Broadcom Fusion network types](https://knowledge.broadcom.com/external/article/303393/understanding-networking-types-in-vmware.html)
