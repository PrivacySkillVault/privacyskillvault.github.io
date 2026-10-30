# Lab 10 — Security Onion standalone monitoring (x86-64 only)

<badge color="warning">Build guide — not yet lab-tested</badge>

Security Onion is a separate network security monitoring platform. It is not an add-on to the Elastic/Wazuh VM. Use a dedicated x86-64 host/VM on the Windows PC and consult the current Security Onion 3 hardware and installation documentation before allocating resources. It does not support Apple-silicon ARM as a native deployment target.

## 1. Resource and topology

For a small standalone learning deployment, start with the vendor's current minimums as the floor, not a production sizing target. Security Onion can require substantial RAM, CPU, disk I/O and storage. Allocate a dedicated VM or spare x86-64 PC; do not run it alongside other full SIEM stacks on a 64 GB host.

Recommended logical interfaces:
- Management interface: MGMT network, static address and gateway as required.
- Monitoring interface: SENSOR network, receives mirrored traffic, no IP/gateway and no management access.
- Optional storage: dedicated SSD-backed virtual disk with sufficient capacity.

The monitoring interface must receive traffic. A NIC attached to an empty private switch sees no network traffic.

## 2. Prepare installer

1. Download the current Security Onion ISO from its official download page.
2. Verify the published checksum.
3. Confirm the target is x86-64 and meets the current hardware requirements.
4. Create a dedicated VM with the supported firmware/virtualisation configuration and enough disk.
5. Attach the ISO and boot.
6. Follow the current installation wizard and choose the Standalone deployment type only for a single-node lab.
7. Configure management networking as requested by the installer.
8. Complete setup and save credentials securely.

Installer prompts and supported deployment modes can change between releases. Use the current official installation guide, not screenshots from older versions.

## 3. Configure packet visibility

Before expecting alerts:
1. Configure the hypervisor or lab firewall to mirror selected endpoint/DMZ traffic to the sensor capture NIC.
2. Confirm the monitoring NIC is assigned as the sniffing interface in Security Onion.
3. Confirm the interface is not used for management, has no default route and does not forward packets.
4. Generate a known benign connection between two lab VMs.
5. Confirm packets are visible using the Security Onion interface and supported capture tooling.

Do not enable promiscuous mode and assume that this creates a mirror. Hypervisor port mirroring or an explicit network tap/bridge is required for traffic not addressed to the sensor.

## 4. Validate ingestion and detections

1. Confirm sensor services and health in the Security Onion interface.
2. Generate benign DNS and HTTP traffic between lab endpoints and the Juice Shop target.
3. Confirm the expected network metadata appears.
4. Inspect the timestamp, source/destination, protocol and sensor interface.
5. If an alert is generated, review the rule/signature and raw event before interpreting it.
6. Document packet loss, capture gaps, rule version and retention.

Security Onion's component set and data schemas are release-dependent. Use the current vendor docs for SOC UI, Hunt, Alerts, Cases, Elastic Agent and sensor health procedures.

## 5. Safe operation

- Never attach the monitoring interface to a bridged home network.
- Never expose the Security Onion management UI to the Internet.
- Use only synthetic traffic generated in the lab.
- Plan disk capacity and retention before storing PCAP.
- Treat packet captures as sensitive; they may contain credentials or personal content.
- Keep Security Onion isolated from other SIEM labs until the network and storage requirements are understood.

## References

- [Security Onion hardware requirements](https://docs.securityonion.net/en/3/dev/hardware/)
- [Security Onion installation](https://docs.securityonion.net/en/3/installation/)
- [Security Onion network architecture](https://docs.securityonion.net/en/3/architecture/)
- [Security Onion documentation](https://docs.securityonion.net/en/3/)
