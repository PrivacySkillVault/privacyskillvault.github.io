# Lab 8 — Network monitoring with Zeek and Suricata

<badge color="warning">Build guide — not yet lab-tested</badge>

This lab introduces passive network visibility. Use a dedicated Linux sensor VM on the Windows x64 PC. Start with a single virtual interface receiving test traffic; add a second sniffing interface only after you understand the hypervisor's port-mirroring capability.

## 1. Understand the sensor topology

A sensor requires a traffic source. Installing Zeek or Suricata does not automatically make it see traffic from other VMs.

Preferred enterprise-style design:
- Sensor management NIC on MGMT.
- Sensor capture NIC on a dedicated SENSOR segment receiving a mirror/SPAN feed from the virtual switch or lab firewall.
- Capture NIC has no IP address, default gateway or forwarding.
- The firewall/router mirrors only the selected lab VLANs.

If the hypervisor cannot mirror traffic to a VM NIC, use a Linux bridge/router VM as an explicit traffic path or run a single-host test with packet capture on the endpoint. Do not claim network-wide visibility from a sensor that only sees its own traffic.

## 2. Prepare Ubuntu sensor

Use a supported Ubuntu Server x86-64 VM with 4 vCPU, 8 GB RAM and sufficient disk for logs/PCAP. Attach the management NIC first. Add the capture NIC only when the mirror path is configured.

Identify interfaces:

```bash
ip -br link
ip -br address
ip route
```

Record which interface is management and which is capture. Do not guess interface names.

For a dedicated capture interface, remove any IP configuration using the network manager actually configured on that guest. Confirm the capture NIC has no IPv4/IPv6 address and no default route before enabling passive capture. Do not remove the management route.

## 3. Install Zeek

Use the official Zeek installation documentation for the Ubuntu release and supported package repository. Repository instructions and package versions change; follow the current installation page rather than adding an unverified third-party PPA.

After installation, verify:

```bash
zeek --version
zeek -N
```

For an offline PCAP test:

```bash
mkdir -p ~/zeek-test && cd ~/zeek-test
zeek -r /path/to/lab-capture.pcap
ls -lah
```

The PCAP must be generated from your own lab. Inspect logs such as conn.log, dns.log and http.log where protocol traffic exists. The presence and exact fields depend on the traffic and Zeek scripts loaded.

For live capture, use the exact interface identified earlier and the supported ZeekControl/deployment configuration for your installed release. Do not start a live capture on the management NIC by accident.

## 4. Install Suricata

Use the official Suricata installation guide for the OS and release. After installation:

```bash
suricata --build-info
suricata --list-runmodes
```

For a safe offline PCAP check:

```bash
sudo suricata -r /path/to/lab-capture.pcap -l ./suricata-output
```

Inspect eve.json and fast.log. A rule match depends on the traffic and ruleset; no alert is expected for arbitrary traffic.

For live capture, follow the current Suricata guide for selecting the interface, run mode, rule update and service configuration. Verify the capture interface is the correct NIC.

## 5. Rule management and updates

Use the official ET Open rules or another rule source whose licence and update method you understand. Update rules using the supported Suricata update tooling for your package. Validate configuration before restart:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Do not copy random IDS rules from untrusted repositories. A rule alert is a signal requiring triage, not proof of compromise.

## 6. Forward logs to SIEM

Forward Zeek and Suricata JSON logs using Elastic Agent integrations or another supported collector. Confirm file paths, permissions, dataset names and integration versions. Ingest a known lab PCAP, then verify:
- Source sensor hostname.
- Event timestamp.
- Source/destination IP and port.
- Protocol and event type.
- Rule signature and category where applicable.
- Original log source and parser.

Avoid ingesting full PCAP continuously until storage and retention are planned. PCAP can contain sensitive credentials or user content; capture only lab traffic and protect the files.

## 7. Validation exercise

1. Generate a benign DNS query from a lab endpoint to the lab DNS resolver.
2. Capture traffic on the mirrored interface.
3. Confirm Zeek logs the DNS transaction.
4. Confirm Suricata processes the capture and writes EVE output.
5. Forward logs to the selected SIEM.
6. Correlate endpoint process event, DNS record and network sensor event by host/IP and time.
7. Document visibility gaps and any asymmetric routing or dropped packets.

## 8. References

- [Zeek documentation](https://docs.zeek.org/en/current/)
- [Zeek installation](https://docs.zeek.org/en/current/install.html)
- [Suricata documentation](https://docs.suricata.io/en/latest/)
- [Suricata installation guide](https://docs.suricata.io/en/latest/install.html)
- [Suricata rule management](https://docs.suricata.io/en/latest/rule-management/index.html)
