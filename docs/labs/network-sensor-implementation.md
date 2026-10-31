# Network sensor deployment — Zeek and Suricata

<badge color="warning">Implementation runbook — live capture requires a proven packet feed</badge>

This page covers a Linux sensor after [Hypervisor Networking](hypervisor-network-implementation.md) is configured. A running Zeek/Suricata process is not proof of visibility. The acceptance test is a known flow visible on the capture NIC and a corresponding local log record.

## 1. Choose sensor role and scope

Use Ubuntu Server on a supported x86-64 host for the Windows lab. On Apple Silicon use an ARM64 Ubuntu guest and verify that the exact Zeek/Suricata release and package source support AArch64. Do not copy x86 package repositories or binaries to ARM.

Starting allocation: 4 vCPU, 8 GB RAM, SSD-backed log volume. Add capacity based on measured packet rate, enabled protocols, JSON volume and retention. Separate the management NIC from capture NICs.

| NIC | Address | Route | Purpose |
|---|---|---|---|
| Management | static/reserved SENSOR-MGMT IP | default route via management router | SSH, updates, time, agent management |
| Capture 1..N | no IP | no default route | mirrored/tap traffic only |

Do not bridge capture NICs, enable IP forwarding, or allow them to route between networks. Record hostname, OS release, architecture, package versions, capture interface MACs, mirror source ports and observed segments.

## 2. Prove capture before installing analyzers

Identify NICs:

~~~bash
ip -br link
ip -br address
ip route
sudo ethtool -k <capture-interface>
~~~

From a controlled endpoint generate a DNS lookup and TCP connection to a known lab target. Capture:

~~~bash
sudo tcpdump -ni <capture-interface> -c 100 'host <source-ip> and host <destination-ip>'
~~~

Expected: packets with the source/destination tuple and timestamps matching the generated test. If the test is not visible, stop and correct the mirror/tap topology. Do not install or tune Zeek/Suricata to compensate for a missing feed.

For deterministic offline analysis, use an authorised lab PCAP and label the exercise **offline PCAP analysis**. Do not describe it as live network monitoring.

## 3. Install prerequisites and record versions

Use official package instructions for the exact Ubuntu release and architecture. Do not add an unverified third-party repository. Record source, repository signing key, package version and installation date.

~~~bash
sudo apt update
sudo apt install -y ca-certificates curl jq tcpdump ethtool logrotate
uname -m
cat /etc/os-release
~~~

Install Zeek and Suricata from their official documented package repositories or distribution-supported packages. Follow current install guides because repository names, package availability and supported architectures change. After install:

~~~bash
zeek --version
zeek -N
suricata --build-info
suricata --list-runmodes
~~~

If either tool is unavailable for the guest architecture/release, do not force an x86 binary or untrusted package. Use a supported x86-64 sensor host, a supported ARM build, or offline PCAP tooling.

## 4. Zeek — enable JSON output deliberately

Zeek's default ASCII log output is not JSON. Enable the documented JSON logging policy in the active Zeek site/local configuration:

~~~text
@load policy/tuning/json-logs
~~~

Apply this in the active Zeek site configuration used by the installed deployment method (for example, local.zeek for a package-managed standalone deployment). Do not create a second conflicting configuration file without checking the active ZeekControl/site configuration.

For offline PCAP, run from a dedicated evidence directory:

~~~bash
mkdir -p ~/psv-zeek-pcap-test
cd ~/psv-zeek-pcap-test
zeek -r /path/to/authorised-lab.pcap
ls -lah
jq -c 'select(.id.orig_h != null)' conn.log | head
~~~

Verify conn.log and dns.log exist when those protocols exist in the PCAP. Inspect JSON keys and timestamps. A PCAP with no DNS traffic will not produce DNS events.

For live mode, configure the capture interface in the installed Zeek deployment (ZeekControl or supported package service), then check the active interface and service status. Do not assume a service name or interface variable across packaging methods. Validate using a known DNS query and TCP connection.

## 5. Suricata — EVE JSON and capture mode

Inspect the installed configuration and service before editing:

~~~bash
suricata --build-info
sudo systemctl status suricata --no-pager
sudo grep -nE '^(af-packet|default-rule-path|rule-files|outputs:)' /etc/suricata/suricata.yaml
~~~

Configure EVE JSON output in the installed /etc/suricata/suricata.yaml using the syntax for that exact release. Enable only required event types initially (alert, anomaly, flow, dns, http, tls as applicable); every enabled type consumes storage and CPU. Preserve the existing YAML structure—do not append a second outputs block.

For live AF_PACKET capture, configure the exact capture NIC(s) in the af-packet section and select the documented run mode for the host. Do not assume AF_PACKET inline IPS settings are equivalent to passive IDS. For a learning sensor, use passive alert/monitoring mode; do not enable inline blocking on a mirror-only NIC.

For offline PCAP:

~~~bash
sudo mkdir -p /var/log/suricata/psv-pcap-test
sudo suricata -r /path/to/authorised-lab.pcap -l /var/log/suricata/psv-pcap-test
sudo test -s /var/log/suricata/psv-pcap-test/eve.json
sudo jq -c 'select(.event_type=="flow" or .event_type=="alert")' /var/log/suricata/psv-pcap-test/eve.json | head
~~~

For live service, validate YAML with the installed Suricata test option before restart (commonly sudo suricata -T -c /etc/suricata/suricata.yaml). Then restart the package service and inspect its journal. Do not copy a run command from a different version without checking suricata --help.

## 6. Rules and safe test traffic

Use official Emerging Threats Open rules or another documented ruleset compatible with the installed Suricata release. Record ruleset version and update date. An empty alert file is not a failure if traffic does not match a signature.

For a safe positive test, use the documented Suricata test signature and test method from current vendor documentation in a fully isolated lab. Confirm the intended packet reaches the capture NIC, Suricata increments packet counters, EVE contains the expected signature/source/destination, and no unexpected IPS drop occurred. Run a negative test using ordinary benign traffic and confirm it does not trigger the test signature.

## 7. Storage, rotation and permissions

Use a dedicated log filesystem or bounded volume where possible. Example logrotate policy skeleton (adjust owner/group and path after verifying the installed service):

~~~text
/var/log/zeek/*.log /var/log/suricata/eve.json {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
~~~

copytruncate has a small log-loss/race window and should not be used blindly for high-volume production collection. Prefer the service's native rotation/reopen mechanism when supported and tested. Confirm the collector account can read active and rotated files without granting world-readable permissions.

Check storage and service health:

~~~bash
df -h
sudo du -sh /var/log/zeek /var/log/suricata 2>/dev/null
sudo journalctl -u suricata -n 100 --no-pager
~~~

Do not continuously retain full PCAP unless capacity, privacy, access and retention are explicitly designed. Keep PCAP separate from SIEM event logs.

## 8. Pre-SIEM acceptance gate

- [ ] Known DNS/TCP test packets visible on capture NIC.
- [ ] Sensor capture interface has no unintended IP/default route.
- [ ] Zeek conn.log contains the test connection; JSON output verified if selected.
- [ ] Zeek dns.log contains the test lookup if DNS was in the capture.
- [ ] Suricata EVE JSON exists and has expected flow/alert records.
- [ ] Positive and negative signature tests recorded.
- [ ] Capture-drop/packet counters reviewed under test load.
- [ ] Sensor hostname, capture scope, timestamps and package versions recorded.
- [ ] Log permissions, rotation and disk bounds verified.
- [ ] Evidence is sanitized and contains no customer/employer traffic.

Do not configure SIEM ingestion until this gate passes. Then follow [Telemetry Collection & Forwarding](telemetry-pipeline.md) and the selected SIEM page.

## References

- [Zeek installation](https://docs.zeek.org/en/current/install.html)
- [Zeek JSON logging](https://docs.zeek.org/en/current/tutorial/logs.html)
- [Suricata documentation](https://docs.suricata.io/en/latest/)
- [Suricata EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [Suricata AF_PACKET configuration](https://docs.suricata.io/en/latest/capture-hardware/af-packet.html)
- [Hyper-V port mirroring](https://learn.microsoft.com/powershell/module/hyper-v/set-vmnetworkadapter)
