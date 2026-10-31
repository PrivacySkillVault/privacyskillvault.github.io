# OPNsense implementation — interface, DHCP, DNS and firewall policy

<badge color="warning">Windows x64 track — reference configuration; verify against installed OPNsense release</badge>

This is the Windows x64 firewall implementation. OPNsense is x86-64; use the separate [ARM64 Ubuntu router guide](mac-arm-router-implementation.md) on Apple Silicon. This page expands the [firewall overview](firewall-routing.md) into an interface and policy procedure.

## 1. Before installation

- Confirm the hypervisor and VM network layout from [Hypervisor Network Implementation](hypervisor-network-implementation.md).
- Create separate WAN, MGMT, ENDPOINT, SERVER, REDTEAM, SENSOR-MGMT and DMZ networks.
- Confirm no subnet overlaps with the home LAN, VPN, Docker/WSL or other lab networks.
- Download the x86-64 OPNsense image from the official site and verify its checksum.
- Keep a hypervisor console and a known-good VM snapshot available.
- Do not attach REDTEAM or DMZ directly to a bridged/physical network.

Starting VM allocation: 2–4 vCPU, 4 GB RAM and 20 GB disk. Increase RAM/storage for IDS and retention. OPNsense virtual hardware requirements depend on enabled services and traffic.

## 2. Install and map interfaces by MAC

Install OPNsense using the current official virtual installation instructions. After first boot, identify each virtual NIC by MAC address and map it to the hypervisor inventory. Do not assume adapter order is stable.

Assign:
- WAN — hypervisor NAT uplink only.
- MGMT — 10.10.10.1/24.
- ENDPOINT — 10.10.20.1/24.
- SERVER — 10.10.30.1/24.
- REDTEAM — 10.10.40.1/24.
- SENSOR-MGMT — 10.10.50.1/24.
- DMZ — 10.10.60.1/24.

Use the interface assignment workflow under Interfaces → Assignments. Enable each assigned interface, give it a clear description and configure static IPv4 addressing for internal segments. Do not configure an internal default gateway. WAN receives its address from the hypervisor NAT network (or the exact static values documented for that network).

After applying, verify the interface status and address on the dashboard and under Interfaces. Test that the admin workstation is connected only to MGMT. Do not enable the WAN web GUI or SSH.

## 3. Initial firewall GUI access and administration

1. Attach a dedicated admin workstation VM to MGMT.
2. Configure it as 10.10.10.10/24 with gateway 10.10.10.1, or use a reservation.
3. Open the OPNsense GUI at https://10.10.10.1 from that workstation.
4. Complete the initial setup wizard, set a unique strong admin password and configure hostname/domain/timezone/NTP.
5. Use HTTPS and the generated certificate; do not permanently disable browser certificate checks.
6. Restrict GUI/SSH to the MGMT interface and named admin host only.
7. Save an encrypted configuration backup before creating the remaining policy.

Do not connect the management workstation to WAN or use the host's physical network as an alternate path.

## 4. Configure DHCPv4 — choose one service

Do not run multiple DHCP servers on the same L2 segment. Current OPNsense offers Dnsmasq, Kea and legacy ISC options; ISC DHCP is end-of-life. For this lab, use **Kea DHCPv4** and do not enable Dnsmasq DHCP on the same interfaces.

Under Services → Kea DHCP → Kea DHCPv4 (menu labels may vary by release):
1. Enable the DHCPv4 service.
2. Select only internal interfaces that should issue leases (typically ENDPOINT, REDTEAM and DMZ; use static/reservations for servers and infrastructure).
3. Enable the basic DHCP firewall rules if the service offers that option.
4. Create one subnet per selected interface:
   - ENDPOINT 10.10.20.0/24, pool 10.10.20.100–10.10.20.199, router 10.10.20.1.
   - REDTEAM 10.10.40.0/24, pool 10.10.40.100–10.10.40.150, router 10.10.40.1.
   - DMZ 10.10.60.0/24, pool 10.10.60.100–10.10.60.150, router 10.10.60.1.
5. Configure DNS server options deliberately:
   - If AD DS is deployed, domain-joined Windows clients must use the DC DNS address (example 10.10.30.10), not public DNS.
   - If there is no AD DNS, use the firewall's Unbound address on the relevant interface and configure Unbound access lists.
6. Configure the domain name/search suffix only for the intended domain.
7. Save/apply and inspect the Kea service log.

Keep SERVER infrastructure hosts on static addresses or explicit reservations. Do not hand out dynamic addresses to the DC, relay, SIEM or firewall. If the DHCP UI automatically adds rules, inspect them and confirm they do not permit unrelated services.

## 5. Configure DNS — choose the correct resolver

### If Active Directory is deployed

- Configure the Windows domain controller with a static SERVER IP (example 10.10.30.10).
- Configure domain members to use only the DC's DNS address.
- Configure the DC's DNS forwarders/recursion according to the Windows Server version and lab policy.
- Do not give domain members public DNS directly; that breaks AD service discovery and can cause inconsistent domain behavior.
- The firewall's Unbound resolver may be used by non-domain guests, but do not configure domain members to bypass AD DNS.

### If Active Directory is not deployed

Use OPNsense Unbound as the lab resolver:
1. Open Services → Unbound DNS → General.
2. Enable Unbound.
3. Select only the internal interfaces that should answer client queries (not WAN).
4. Enable DNSSEC validation if the chosen upstream design supports it.
5. Configure access lists to allow only the required lab subnets.
6. Apply and test from one endpoint using nslookup/dig.
7. Confirm queries from REDTEAM/DMZ follow the intended policy and cannot access management interfaces.

Do not run two DNS services on the same address/port. If Dnsmasq DNS is selected instead of Unbound, document that choice and disable conflicting listeners.

## 6. Create aliases before writing rules

Under Firewall → Aliases create named aliases for:
- PSV_MGMT_ADMIN — 10.10.10.10.
- PSV_DC_DNS — 10.10.30.10 (only if AD DS is deployed).
- PSV_LOG_RELAY — 10.10.30.30.
- PSV_SIEM — the one selected SIEM host.
- PSV_DMZ_TARGET — the approved target address (example 10.10.60.10).
- PSV_MGMT_NET, PSV_ENDPOINT_NET, PSV_SERVER_NET, PSV_REDTEAM_NET, PSV_SENSOR_MGMT_NET and PSV_DMZ_NET.

Create port aliases:
- PSV_AD_TCPUDP_CORE — TCP/UDP 53, 88, 389 and 464.
- PSV_AD_TCP_CORE — TCP 135, 445, 636, 3268, 3269 and 9389, only when the corresponding service is used.
- PSV_AD_RPC_DYNAMIC — TCP 49152–65535, only where required for the installed Windows Server roles/operations.
- PSV_NTP — UDP 123.
- SIEM receiver aliases only for the selected product and actual configured ports.

Use the firewall policy matrix and current Microsoft AD port requirements. Do not create a broad any-to-any pass rule.

## 7. Build inbound interface rules

OPNsense rules are applied on the interface where traffic enters. Add rules to the source interface, not the destination interface. Keep the default deny policy and put narrow allow rules above any broader rules. Enable logging on selected validation rules.

### MGMT interface

1. Allow PSV_MGMT_ADMIN to the firewall GUI on TCP/443.
2. Allow PSV_MGMT_ADMIN to firewall SSH on TCP/22 only if SSH administration is required.
3. Allow MGMT admin host to the named server management ports that are actually needed.
4. Deny/log other management access from non-admin clients.
5. Do not allow MGMT to reach the home LAN unless explicitly required.

### ENDPOINT interface

If AD DS is deployed, add narrow rules from ENDPOINT net to PSV_DC_DNS:
- TCP/UDP ports in PSV_AD_TCPUDP_CORE.
- TCP ports in PSV_AD_TCP_CORE only for services required.
- TCP dynamic RPC range only if required for domain operations/GPO/remote management; scope destination to the DC.
- UDP/123 to the designated NTP source.

Add DNS rules to the DC only. Do not permit ENDPOINT to query arbitrary Internet DNS directly when domain DNS is required. Add SIEM agent/forwarder access later, only after Stage 8 and only to PSV_SIEM/required service ports.

### REDTEAM interface

Allow only the approved assessment source(s) to PSV_DMZ_TARGET on the explicitly selected test ports. Use a time-bounded rule and enable logging. Deny REDTEAM to MGMT, SERVER, ENDPOINT, SENSOR-MGMT and the home LAN.

### DMZ interface

Do not permit DMZ-initiated connections to MGMT, SERVER, ENDPOINT, REDTEAM, SENSOR-MGMT or the home LAN. Allow only narrowly required egress (for example, package updates) during a controlled maintenance window. Remove update egress before assessments.

### SENSOR-MGMT interface

Allow sensor administration only from PSV_MGMT_ADMIN to the sensor's management address on required SSH/HTTPS ports. Do not use this interface as a capture feed. The sensor's capture NIC is separate, has no IP/default gateway and must receive a verified mirror/tap feed.

### SERVER interface

Allow only required service-to-service flows:
- Endpoints to DC/DNS for AD services.
- Firewall/router devices to PSV_LOG_RELAY on the selected syslog transport/port.
- Relay/sensor/endpoint agents to the selected SIEM on the product-specific ports.
- Management workstation to SIEM UI/API only where required.
Do not permit REDTEAM/DMZ to access server management ports.

## 8. NAT and controlled update egress

Keep outbound NAT in the documented default/automatic mode unless the lab design requires a specific manual mapping. Confirm internal source networks are translated through WAN. WAN is connected to the hypervisor NAT uplink, not directly to REDTEAM/DMZ.

For initial package updates, add temporary egress rules from only the infrastructure hosts that need updates. Prefer DNS + HTTP/HTTPS and only to the intended upstream path. Remove broad egress after updates. Do not create inbound WAN port forwards for management.

## 9. Firewall logging and remote forwarding

1. Enable logging on the specific pass/block rules used for acceptance tests.
2. Open Firewall → Log Files → Live View and verify source, destination, port, interface, rule and action.
3. Configure remote logging to PSV_LOG_RELAY using the selected TCP/TLS transport and source address.
4. Select only required system/firewall facilities; do not forward every facility by default.
5. Confirm the event appears in the relay's source-specific file before installing any SIEM agent.
6. Configure Suricata EVE forwarding separately if IDS alert records are required.

Keep local firewall logs enabled and retain an encrypted OPNsense configuration backup.

## 10. Suricata IDS — passive alert-only first

Only after interfaces and firewall rules are stable:
1. Open Services → Intrusion Detection.
2. Select the intended internal interfaces that carry routed traffic; WAN-only monitoring after NAT may lose original internal source identity.
3. Select a compatible ruleset and record its version/update date.
4. Enable EVE JSON output and only the required event types.
5. Start in IDS/alert-only mode. Do not enable inline IPS blocking until the passive path is proven and you understand the hypervisor NIC/run mode support.
6. Generate a known test flow and a safe positive signature test in the isolated lab.
7. Verify packet counters, alert record and local log; forward the EVE record to the relay only after local proof.

## 11. Acceptance and recovery

- [ ] All seven interfaces map to the intended networks and MAC inventory.
- [ ] Each internal interface has the intended static address.
- [ ] WAN reaches only the hypervisor NAT uplink.
- [ ] DHCP leases come from one service only; no overlapping scope.
- [ ] Domain members use DC DNS, or non-domain clients use the selected Unbound resolver.
- [ ] Admin GUI/SSH is reachable only from the named management host.
- [ ] ENDPOINT-to-DC flows work only on required AD ports.
- [ ] REDTEAM can reach only the approved DMZ target/ports.
- [ ] DMZ cannot initiate to trusted segments.
- [ ] SENSOR-MGMT is management-only; capture NIC is separate and mirror visibility is proven.
- [ ] Firewall pass/block logs show the expected rule and tuple.
- [ ] Firewall events arrive in the relay file before SIEM installation.
- [ ] Suricata EVE events are visible locally before forwarding.
- [ ] Config backup is saved and restore procedure is known.

If an interface or rule change breaks management, use the hypervisor console to restore the last known-good config backup. Do not expose the GUI on WAN as a recovery shortcut.

## References

- [OPNsense interface configuration](https://docs.opnsense.org/manual/interfaces.html)
- [OPNsense DHCP services](https://docs.opnsense.org/manual/dhcp.html)
- [OPNsense Kea DHCP](https://docs.opnsense.org/manual/kea.html)
- [OPNsense Unbound DNS](https://docs.opnsense.org/manual/unbound.html)
- [OPNsense firewall rules](https://docs.opnsense.org/manual/firewall.html)
- [OPNsense firewall log live view](https://docs.opnsense.org/manual/logging_firewall.html)
- [OPNsense remote logging](https://docs.opnsense.org/manual/settingsmenu.html)
- [Microsoft Active Directory port requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
