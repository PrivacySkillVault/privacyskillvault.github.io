# Lab firewall policy matrix — least-privilege flows

<badge color="warning">Policy design reference — adapt to enabled services and verify with packet/log tests</badge>

This page defines the intended inter-segment policy before writing individual OPNsense/nftables rules. It is not a substitute for inspecting the actual services enabled on each VM. Start with deny-by-default between segments, then add only the required flows below. Keep WAN management closed.

## 1. Address and role assumptions

| Role | Example address | Segment |
|---|---:|---|
| OPNsense internal gateways | .1 in each subnet | all internal segments |
| PSV-DC01 (AD DS/DNS) | 10.10.30.10 | SERVER |
| PSV-LOG01 (syslog relay) | 10.10.30.30 | SERVER |
| SIEM host (one at a time) | Elastic 10.10.30.20; Splunk 10.10.30.21; Wazuh 10.10.30.22 | SERVER |
| Management workstation | 10.10.10.10 | MGMT |
| Windows endpoint | DHCP/reservation in 10.10.20.0/24 | ENDPOINT |
| Kali | DHCP/reservation in 10.10.40.0/24 | REDTEAM |
| Vulnerable target | 10.10.60.20 | DMZ |

Replace these addresses consistently if your actual plan differs. Do not copy a sample rule before checking source/destination interface and address.

## 2. Default policy

| Source | Destination | Default |
|---|---|---|
| MGMT admin workstation | router/server management | Allow only required management ports |
| ENDPOINT | DC/DNS | Allow only domain/DNS/NTP services actually used |
| ENDPOINT | relay/SIEM | Allow selected agent/forwarder destinations after SIEM stage |
| REDTEAM | named DMZ target | Allow only approved test ports during a test window |
| REDTEAM | MGMT/SERVER/ENDPOINT/home LAN | Deny |
| DMZ | MGMT/SERVER/ENDPOINT/home LAN | Deny initiation |
| SENSOR capture NIC | any routed network | Deny; capture NIC is not a management interface |
| WAN | router/VM management | Deny inbound |
| Internal segments | Internet | Deny by default; temporary controlled update egress only |

Use stateful return traffic for allowed sessions. Log selected deny rules and selected test allow rules; do not enable noisy logging on every packet indefinitely.

## 3. AD DS/DNS client-to-domain-controller flows

The following are common AD DS dependencies, not a command to open every port unconditionally. Select based on installed roles/features and Microsoft guidance.

| Protocol | Port | Use |
|---|---:|---|
| TCP/UDP | 53 | DNS |
| TCP/UDP | 88 | Kerberos |
| TCP/UDP | 389 | LDAP |
| TCP | 445 | SMB/SYSVOL/Group Policy |
| TCP/UDP | 464 | Kerberos password change |
| TCP | 135 | RPC endpoint mapper |
| TCP | 49152–65535 | Modern Windows dynamic RPC range (default) |
| TCP | 3268 | Global Catalog, if used |
| TCP | 3269 | Global Catalog over TLS, if used |
| TCP | 636 | LDAP over TLS, if configured |
| UDP | 123 | NTP to the selected time source |
| TCP | 9389 | AD Web Services, if management tools require it |

Some Windows versions/roles use additional ports. The dynamic RPC range can be narrowed on the DC only if the change is supported, documented and consistently applied. Do not arbitrarily open or shrink it. Verify DNS SRV lookup, domain join, Group Policy, Kerberos authentication and administrative tools after adding rules.

**DNS when AD DS is not deployed:** if clients use OPNsense Unbound or the Mac router's dnsmasq resolver, allow only the relevant client subnet to the router's own interface address on UDP/53 and TCP/53. Configure Unbound access lists or bind dnsmasq only to the intended internal interfaces. Do not allow arbitrary client DNS directly to public resolvers. If AD DS is deployed, domain members should use the DC DNS address; do not silently fall back to the router/public DNS because that can break AD SRV discovery.

## 4. SIEM and telemetry ports — only enable selected stack

| Stack/component | Typical port | Initiator → destination | Notes |
|---|---:|---|---|
| Elastic Fleet Server | TCP 8220 | Elastic Agents → Fleet Server | Confirm configured Fleet URL/port |
| Elastic Elasticsearch API | TCP 9200 | Fleet Server/agents as configured → Elasticsearch | Restrict to required hosts; TLS/auth |
| Kibana | TCP 5601 | MGMT workstation → Kibana | Management only |
| Splunk receiver | TCP 9997 | Universal Forwarders → Splunk Enterprise | Configure receiving explicitly |
| Splunk Web | TCP 8000 | MGMT workstation → Splunk | Management only |
| Splunk management API | TCP 8089 | Admin/forwarder management paths only | Never expose to untrusted networks |
| Wazuh agent channel | TCP 1514 | Agents → Wazuh manager | Secure agent channel; verify release |
| Wazuh enrollment | TCP 1515 | New agents → Wazuh manager | Restrict; can be disabled after enrollment depending on design |
| Wazuh syslog input | TCP/UDP 514 | Approved syslog senders → manager | Optional direct syslog input; configure allowed-ips and verify exact release |
| Wazuh indexer | TCP 9200 | Wazuh components → indexer | Internal only; TLS/auth |
| Wazuh dashboard | TCP 443 or configured port | MGMT workstation → dashboard | Use actual deployment port |

Do not enable all rows simultaneously. Select one SIEM, follow its version-specific guide, then add only the required rules. Some Elastic deployments use different ports/paths depending on Fleet topology. Consult the product's port documentation.

## 5. Syslog relay

For the relay runbook's isolated TCP example:
- Allow TCP/514 from the exact OPNsense/Mac-router source addresses to PSV-LOG01 only. The Windows and Mac examples are separate lab islands and may reuse 10.10.30.1; if both send to one relay, first assign unique non-overlapping source IPs/subnets.
- Deny TCP/514 from WAN, home LAN, REDTEAM, DMZ and unrelated clients.
- If syslog crosses an untrusted or multi-host network, use TLS and validate certificates. TCP alone is not encryption or sender authentication.

## 6. Management access

Permit SSH/RDP/HTTPS only from the named MGMT admin workstation to named hosts. Avoid broad any-to-any management rules. Keep hypervisor host management protected by host OS firewall and strong authentication. Do not expose RDP, SSH, Kibana, Splunk Web, Wazuh dashboard or firewall GUI on WAN.

## 7. Rule creation and validation sequence

For OPNsense:
1. Create aliases for lab subnets, servers, management host and approved targets.
2. Create rules on the interface where traffic enters; OPNsense rules are evaluated on ingress interface.
3. Add the narrowest source, destination, protocol and destination port.
4. Enable logging for explicit validation rules.
5. Apply and inspect rule order; a broad pass rule above a narrow block can invalidate the design.
6. Test allowed and denied flows from the source host.
7. Confirm the live firewall log records expected interface, rule, action and tuple.
8. Export an encrypted configuration backup after the policy is stable.

For the Mac nftables router:
1. Use interface-specific input/forward rules and explicit source/destination sets.
2. Keep default-drop policies.
3. Add only the required flows to the ruleset; syntax-check before applying.
4. Check counters and unique log prefixes for both allowed and denied flows.
5. Re-run the policy tests after reboot.

## 8. Negative tests — required

- ENDPOINT cannot connect to router SSH or management UI.
- REDTEAM cannot connect to MGMT, DC management ports or home LAN.
- DMZ cannot initiate to SERVER, ENDPOINT or MGMT.
- Unapproved hosts cannot reach the syslog relay listener.
- No SIEM management port is reachable from REDTEAM or DMZ.
- No IPv6 route bypasses the IPv4 policy.
- No VM has a second bridged/NAT adapter that bypasses the firewall.

A failed ping is not sufficient. Test the actual TCP/UDP service ports and inspect firewall counters/logs. Record test source, destination, port, time, expected result, actual result and rule identifier.

## References

- [Microsoft Active Directory and Active Directory Domain Services port requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [Microsoft Windows dynamic port range](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)
- [OPNsense firewall rules](https://docs.opnsense.org/manual/firewall.html)
- [Wazuh remote syslog configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html)
- [Splunk receiving and forwarding](https://docs.splunk.com/Documentation/Splunk/latest/Forwarding/Enableareceiver)
- [Elastic networking requirements](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html)
