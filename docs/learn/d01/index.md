# D01 — Infrastructure & Platform Foundation

Understand the systems and network services on which applications and security controls depend.

## Learning areas

- Networking: Ethernet, IPv4/IPv6, subnetting, routing, switching, VLANs, TCP/UDP, DNS, DHCP, HTTP/S, and TLS.
- Linux: users and permissions, processes, services, storage, filesystems, logs, SSH, and systemd.
- Windows: accounts, services, Event Viewer, PowerShell, process creation, and basic domain concepts.
- Virtualisation and containers: hypervisors, virtual networks, images, containers, and resource allocation.
- Platform operations: storage, CPU and memory, backups, patching, and availability.

## Practical exercise

Build a small isolated network with one Linux system and one Windows system. Document the addressing plan, DNS resolution, connectivity tests, user permissions, service status, and relevant system logs.

## Evidence to record

Environment and software versions; network diagram and private lab IP plan; commands and expected results; troubleshooting and root cause; security implications and references.

D02 uses this foundation to understand telemetry. D04 uses it to correlate endpoint, identity, and network evidence.

## Protocol and addressing references

Use primary protocol specifications when documenting network behaviour. Examples include:

- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) and [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — DNS concepts and implementation.
- [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) — IPv4 private address allocation.
- [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) — IPv4 documentation address blocks; these are for examples and documentation, not real public endpoints.
- [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291) — IPv6 addressing architecture.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) — TLS 1.3 protocol.
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) — HTTP semantics.

An RFC is a publication series, not a guarantee that every RFC is an Internet Standard. Check each document's status and updates on the RFC Editor site before treating it as a normative requirement.
