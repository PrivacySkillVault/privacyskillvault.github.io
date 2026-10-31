# Mac ARM64 lab — Linux router and firewall

<badge color="warning">Mac-only alternative — not OPNsense, not yet hardware-tested</badge>

Apple-silicon Macs cannot run OPNsense as an ARM64 guest because OPNsense supports x86-64. This guide uses Ubuntu Server ARM64 with nftables for a segmented Mac-only lab. It is not a feature-equivalent OPNsense replacement. If OPNsense is mandatory, use a separate x86-64 physical appliance or the Windows x64 OPNsense VM.

## 1. Preconditions

- Apple-silicon Mac and VMware Fusion.
- Fusion release that exposes enough independent custom/private host networks.
- Ubuntu Server ARM64 ISO from Ubuntu.
- No REDTEAM or DMZ guest connected to Bridged networking.

If the installed Fusion release cannot create independent networks for the segments below, stop. Do not pretend one host-only network provides segmentation.

## 2. Create Fusion networks

Open Fusion network preferences and inspect available networks. Keep the default NAT network for router WAN only. Create independent private/host-only networks for MGMT, ENDPOINT, SERVER, REDTEAM and DMZ. Disable Fusion DHCP on internal networks if the Linux router will provide DHCP; otherwise use static addressing consistently and do not enable a second DHCP server.

| Network | Subnet | Router address |
|---|---|---|
| MGMT | 10.10.10.0/24 | 10.10.10.1 |
| ENDPOINT | 10.10.20.0/24 | 10.10.20.1 |
| SERVER | 10.10.30.0/24 | 10.10.30.1 |
| REDTEAM | 10.10.40.0/24 | 10.10.40.1 |
| DMZ | 10.10.60.0/24 | 10.10.60.1 |

Record the actual Fusion network names and verify subnets before configuring guests. If Fusion assigns different ranges, change the plan consistently.

## 3. Create the Ubuntu ARM64 router VM

1. Download Ubuntu Server ARM64 and verify its published checksum.
2. Create PSV-MAC-RTR01 with 2–4 vCPU, 4 GB RAM and 30 GB disk.
3. Add six adapters: NAT for WAN and one for each internal segment.
4. Install Ubuntu Server and create a named sudo user.
5. Update, reboot and identify interfaces/MAC addresses:

    uname -m
    ip -br link
    ip -br address
    ip route

Expected architecture is aarch64. Record every NIC MAC and map it to its Fusion network before configuration. Do not guess interface names.

For the full MAC-matched Netplan YAML, persistent IPv4 forwarding, explicit IPv6 policy, nftables baseline, DHCP/DNS decision, logging and rollback procedure, use the [Mac ARM Router Implementation Runbook](mac-arm-router-implementation.md).

## 4. Configure interface addressing

Use Netplan MAC matching so Linux interface enumeration changes do not silently swap network roles. Configure:
- WAN: DHCP from Fusion NAT; this is the only interface with a default route.
- MGMT: 10.10.10.1/24.
- ENDPOINT: 10.10.20.1/24.
- SERVER: 10.10.30.1/24.
- REDTEAM: 10.10.40.1/24.
- DMZ: 10.10.60.1/24.

Use the actual MAC values in Netplan. Do not set default gateways on internal interfaces. Validate Netplan before applying; keep the Fusion console open in case remote access is lost.

## 5. Enable routing and firewall

Install the Ubuntu-supported nftables package. Enable IPv4 forwarding using a persistent sysctl setting and verify it is active. Keep IPv6 forwarding disabled unless you have designed and tested an equivalent IPv6 policy; an IPv4-only ruleset must not leave an IPv6 bypass.

Create a persistent nftables ruleset with:
- Default-drop input and forward chains.
- Loopback and established/related traffic allowed.
- Management access only from the named MGMT admin host.
- Explicit DNS/NTP, AD DS and telemetry flows added only when required.
- REDTEAM-to-DMZ limited to the written target IP/ports.
- DMZ-to-MGMT/SERVER/ENDPOINT/home LAN denied.
- Source NAT only for the selected internal subnets allowed temporary update egress.

Build and validate rules from the Fusion console. Use nftables syntax-check mode before applying a file. Keep a known-good snapshot and do not paste an unreviewed generic firewall script into a live host.

## 6. DHCP and DNS

Start with static addresses to prove routing and firewall policy. Once stable, add one DHCP service (for example, dnsmasq) on the router and one non-overlapping scope per client segment. Disable Fusion DHCP on those segments. For an AD domain, domain clients must use the domain controller for DNS; configure forwarding/resolution deliberately.

## 7. Validate isolation

From each guest:

    ip -br address
    ip route
    ip neigh

Test:
- Each guest reaches its own router interface.
- Only explicitly allowed cross-segment services work.
- Kali reaches only the scoped DMZ target.
- DMZ cannot initiate to MGMT, SERVER, ENDPOINT or home LAN.
- No guest has a second NAT or Bridged NIC bypassing the router.

Check nftables counters/logs for allowed and denied flows. Ping failure is not sufficient evidence.

## 8. Firewall logging

Add nftables log statements to selected deny rules with a unique prefix. Verify the messages appear locally in journald. Configure rsyslog to write those messages to a dedicated file, then follow [Telemetry Collection & Forwarding](telemetry-pipeline.md). Do not assume nftables automatically exports logs remotely.

## 9. Limitations

This Linux router does not provide OPNsense's GUI, DHCP/DNS integration, Suricata plugin or configuration backup interface. Install ARM64 Zeek/Suricata separately only after verifying package support and packet visibility. Do not claim full network visibility without a proven mirror/tap or inline path.

## References

- [Ubuntu Server documentation](https://ubuntu.com/server/docs)
- [Linux nftables documentation](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
- [Broadcom Fusion networking types](https://knowledge.broadcom.com/external/article/303393/understanding-networking-types-in-vmware.html)
- [Apple Silicon guest compatibility in Fusion](https://knowledge.broadcom.com/external/article/315602)
