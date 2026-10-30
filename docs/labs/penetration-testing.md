# Lab 9 — Isolated penetration-testing environment

<badge color="warning">Build guide — not yet lab-tested</badge>

This is a controlled assessment lab. Only scan or test the targets you own and have deliberately placed in the isolated lab segment. Do not use the lab network as a bridge to your home, employer or public networks.

## 1. Topology

- Kali Linux: REDTEAM network, no bridged adapter.
- OWASP Juice Shop: DMZ network, no direct home LAN access.
- Optional Ubuntu target: DMZ network, patched base OS with a deliberately vulnerable application only.
- Admin workstation: MGMT only.
- Firewall/router: explicit allow from Kali to target IP and ports only.

Use the Windows PC for x86-64 targets or Mac for ARM64 Kali and container images with a matching platform manifest. Verify Docker images support the guest architecture before pulling.

## 2. Install OWASP Juice Shop with Docker

Use a supported Docker Engine installation on a disposable Ubuntu target VM connected only to DMZ. Follow Docker's official install guide for that Ubuntu release.

After installing Docker, verify:

\`\`\`bash
docker version
docker info
\`\`\`

Run the official OWASP Juice Shop image on the DMZ interface only. First inspect image metadata and confirm platform support. Bind the application port to the target VM's DMZ address, not to all host interfaces:

\`\`\`bash
docker pull bkimminich/juice-shop
docker run -d --name juice-shop --restart unless-stopped \
  -p 10.10.60.20:3000:3000 bkimminich/juice-shop
docker ps
\`\`\`

Replace 10.10.60.20 with the actual DMZ address assigned to the target VM. If the image does not publish a compatible ARM64 manifest, use a supported x86-64 target on the Windows PC rather than assuming emulation is suitable.

From Kali, confirm only the intended application port is reachable:

\`\`\`bash
curl -I http://10.10.60.20:3000
\`\`\`

Do not expose this service on the home LAN or public Internet. Do not use default port mapping without binding to the lab interface.

## 3. Establish a test scope

Create a written scope file with:
- Authorised tester VM/IP.
- Target VM/IP and application URL.
- Permitted ports and protocols.
- Test window.
- Excluded systems and networks.
- Stop conditions.
- Data handling and cleanup.

Example scope: Kali 10.10.40.10 may assess Juice Shop 10.10.60.20 TCP/3000 only. No other addresses or ports are in scope.

## 4. Reconnaissance and service identification

From Kali, first confirm the target address and then scan only the target and port in scope:

\`\`\`bash
nmap -sT -sV -p 3000 10.10.60.20
\`\`\`

Record the command, Nmap version, time, target and output. Do not use broad subnet scans until the lab's authorised scope explicitly permits them.

## 5. Web assessment workflow

Use browser developer tools and Burp Suite Community:
1. Configure the browser to proxy through Burp's local listener.
2. Confirm only the browser traffic for the Juice Shop lab is proxied.
3. Browse the application and map routes, requests, authentication state and API endpoints.
4. Test input validation, authentication and session handling, access control, business logic and error handling using the OWASP Web Security Testing Guide as the methodology.
5. Use harmless test data and avoid destructive actions.
6. Capture request/response evidence with secrets and personal data redacted.
7. Record finding, impact, reproducible steps, evidence, remediation and retest result.

Do not run destructive exploit chains, denial-of-service tests or tests against public sites as part of this lab.

## 6. Vulnerability verification and remediation

For each finding:
- Reproduce in the isolated target.
- Identify the affected component and version.
- Check the vendor advisory and relevant OWASP guidance.
- Explain preconditions and impact.
- Propose a fix.
- Apply the fix or configuration change in a separate snapshot.
- Repeat the exact test and record whether it is resolved.

A scanner finding is not confirmed until manually validated. Avoid presenting tool output alone as proof of exploitability.

## 7. Cleanup

Stop and remove the disposable target when finished:

\`\`\`bash
docker stop juice-shop
docker rm juice-shop
\`\`\`

Revert the target VM snapshot. Remove temporary firewall allows and verify that the target is no longer reachable from Kali or any other network.

## 8. References

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [Juice Shop official repository and Docker usage](https://github.com/juice-shop/juice-shop)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Nmap reference guide](https://nmap.org/book/man.html)
- [Docker Engine installation](https://docs.docker.com/engine/install/)
