# Lab — Network monitoring before SIEM

<badge color="warning">Mandatory source stage — build and validate before SIEM</badge>

This lab builds and proves network telemetry sources. Do not postpone it until after Elastic, Splunk or Wazuh. A SIEM cannot ingest firewall/IDS/Zeek data that has not been generated and exposed to a collector.

## 1. Visibility model

There are two distinct sources:
1. **Firewall telemetry:** OPNsense rule pass/block events and OPNsense Suricata IDS alerts. The firewall generates these and exports them through remote syslog/EVE syslog.
2. **Packet-sensor telemetry:** Zeek connection/DNS logs and standalone Suricata EVE JSON. The sensor must actually receive packets. Installing the software or enabling promiscuous mode does not create a mirror.

Start with firewall logging and OPNsense IDS. Add Zeek only after the packet feed is proven.

## 2. Windows x64 — OPNsense IDS

Complete [Firewall & Routing](firewall-routing.md) first.

1. Enable logging on firewall rules used for allow/deny tests.
2. Enable Suricata in alert-only IDS mode on internal interfaces carrying the traffic.
3. Set HOME_NET to the lab subnets.
4. Update the selected ruleset and check service health.
5. Generate known allowed and denied flows.
6. Verify firewall logs and IDS alerts locally.
7. Enable EVE/syslog output and prove an alert reaches the relay.

Do not begin with IPS blocking. Measure CPU, packet loss, false positives and recovery first. OPNsense documents capture-mode and driver/offload requirements.

## 3. Zeek sensor topology

Use a supported Ubuntu Server sensor VM. Suggested starting resources: 4 vCPU, 8 GB RAM and SSD-backed log storage.

- Management NIC: MGMT, static/reserved address and management route.
- Capture NIC: only a validated mirror/tap or explicit inline capture path; no IP, gateway or forwarding.
- An empty SENSOR virtual network does not supply traffic.

Visibility options:
- **Hyper-V:** configure virtual switch port mirroring only when source and destination adapters share the relevant switch. Set source/destination roles and verify with known traffic.
- **VMware Workstation/Fusion:** do not assume a universal SPAN feature. Use a supported physical mirror/tap, OPNsense IDS for routed visibility or offline lab PCAP.
- **VirtualBox:** promiscuous mode is not a global mirror across internal networks. Use offline PCAP or a separately validated topology.

Record exactly which segments/interfaces are visible. A sensor on one segment cannot see all other segments without a real feed.

## 4. Install and verify Zeek

Install Zeek using official instructions for the exact Ubuntu release and architecture. Record package version and method.

    zeek --version
    zeek -N

For a lab-owned PCAP:

    mkdir -p ~/zeek-test
    cd ~/zeek-test
    zeek -r /path/to/lab-capture.pcap
    ls -lah

Inspect conn.log and dns.log when those protocols exist in the PCAP. Enable Zeek's documented JSON logging policy before forwarding. Verify JSON records contain expected timestamp, source/destination and protocol fields.

For live capture, use the exact interface identified by MAC and supported ZeekControl/deployment method. Do not capture on the management NIC accidentally.

## 5. Install and verify standalone Suricata (optional)

Use official Suricata packages for the guest OS and architecture. Record version and ruleset.

    suricata --build-info
    suricata --list-runmodes

For offline PCAP:

    sudo suricata -r /path/to/lab-capture.pcap -l ./suricata-output
    ls -lah ./suricata-output

Inspect eve.json. EVE contains JSON events such as alerts, anomalies and protocol metadata when enabled/applicable. Arbitrary traffic is not expected to trigger an alert; use documented safe test traffic.

For live capture, confirm interface and run mode. Validate packet counters and dropped-packet metrics.

## 6. Local log validation

Before forwarding:
- Zeek logs exist and are JSON if configured.
- Suricata eve.json exists and contains expected event types.
- Collector can read the files.
- Rotation/retention is configured.
- Sensor host/interface/capture scope are documented.
- Timestamp and event identity are preserved.

Do not store full PCAP continuously until retention, capacity and sensitive-data handling are planned.

## 7. Forwarding prerequisites

Follow [Telemetry Collection & Forwarding](telemetry-pipeline.md). The later SIEM collector monitors Zeek/Suricata files on the sensor. OPNsense firewall/IDS syslog flows through the Linux relay.

The SIEM build is blocked until firewall pass/block events, OPNsense Suricata alerts, endpoint source events and (if selected) proven Zeek/Suricata sensor logs exist.

## References

- [OPNsense IDS/IPS and Suricata](https://docs.opnsense.org/manual/ips.html)
- [OPNsense remote logging](https://docs.opnsense.org/manual/settingsmenu.html)
- [Zeek documentation](https://docs.zeek.org/en/current/)
- [Zeek installation](https://docs.zeek.org/en/current/install.html)
- [Zeek JSON logs](https://docs.zeek.org/en/current/tutorial/logs.html)
- [Suricata documentation](https://docs.suricata.io/en/latest/)
- [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
