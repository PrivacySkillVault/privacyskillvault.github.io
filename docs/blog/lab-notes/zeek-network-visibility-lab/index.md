# Lab Notes: Understanding Network Activity with Zeek Logs

<small>LAB NOTES · NETWORK MONITORING · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← Lab Notes</a><span> / </span><a href="../../">Cyber Journal</a></p>

Zeek is a network security monitoring platform that produces structured logs from observed traffic. Rather than treating every packet as an isolated event, an analyst can use protocol-aware records to understand connections, DNS activity, HTTP requests, and other network behaviour.

This lab note introduces three useful log types: conn.log, dns.log, and http.log. It is a learning guide, not a claim that a live lab has already been executed.

## 1. Understand the sensor position

Zeek can only analyse traffic it can observe. A sensor connected to an ordinary switched access port may see only its own traffic unless the network is configured to mirror or otherwise deliver relevant traffic.

In a home lab, use a virtual network or a switch mirror/monitor port that you control. Do not capture traffic from networks or users without permission. Prefer synthetic or public test traffic and avoid collecting credentials or private user content.

## 2. The three logs

| Log | What it records | Useful questions |
|---|---|---|
| conn.log | TCP, UDP and ICMP connection metadata | Which hosts communicated, using what ports, and for how long? |
| dns.log | DNS query and response metadata | Which names were queried, what type was requested, and what response code returned? |
| http.log | HTTP request/response metadata when visible | Which host and URI were requested, and what response was observed? |

The exact fields depend on Zeek version, enabled analyzers, protocol visibility, and configuration.

## 3. A simple correlation workflow

1. Find a connection in conn.log using the source and destination addresses, ports, protocol, and time.
2. Check whether the same originator made a DNS query shortly before the connection.
3. If HTTP is visible, review host, method, URI, status code, and user-agent fields.
4. Correlate using time and available identifiers such as Zeek connection UID.
5. Compare the activity with expected applications and known services.

A DNS query followed by a connection to the resolved address may be consistent with normal browsing. It is not automatically evidence of command-and-control.

## 4. What encrypted traffic changes

HTTPS and other encrypted protocols limit what a passive sensor can read from application payloads. Depending on protocol, configuration, and metadata availability, Zeek may still observe connection properties and some handshake metadata, but it cannot simply reveal the full encrypted URL path or content.

Do not assume that absence of an HTTP record means no web activity occurred. Consider TLS, QUIC, DNS over HTTPS, sensor placement, packet loss, and analyser support.

## 5. Safe lab validation

Generate ordinary test traffic from a VM you control:

- Resolve a documentation hostname.
- Open a public HTTPS website.
- Connect to a service inside your own isolated lab.
- Record the test start and end times.

Then inspect the logs and identify which records correspond to your actions. Do not scan or probe third-party systems as part of this exercise.

## 6. Common pitfalls

- Sensor does not receive both directions of traffic.
- Traffic is encrypted and the analyst expects payload visibility.
- Packet loss or capture filters hide events.
- DNS is cached locally, so a new DNS query is not generated.
- Timestamps are compared without timezone normalisation.
- Analysts correlate only by IP address and ignore ports, protocol, and time.
- A notice or weird log is treated as a confirmed attack without context.

## 7. What a good lab record includes

Document Zeek version, interface or virtual network topology, capture source, traffic-generation method, enabled scripts, log format, sample records with private values removed, and the limitations observed.

## References

- [Zeek documentation — Common Logs](https://docs.zeek.org/en/current/reference/logs/index.html)
- [Zeek conn.log reference](https://docs.zeek.org/en/lts/reference/logs/conn.html)
- [Zeek Quick Start](https://docs.zeek.org/en/current/quickstart.html)

*Lab status: learning guide only. Mark the exercise as completed and attach your own screenshots only after reproducing it in an authorised lab.*