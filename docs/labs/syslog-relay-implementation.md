# Linux telemetry relay — rsyslog implementation

<badge color="warning">Pre-SIEM configuration — isolated TCP baseline; TLS hardening is a separate required decision</badge>

This guide configures a dedicated Linux relay on SERVER to receive firewall/router syslog and write bounded, source-specific files. It does not install a SIEM agent. The pre-SIEM acceptance gate is that messages arrive from known sources and are written to the correct files with timestamps and source identity intact.

## 1. Addressing and firewall prerequisites

Example relay: PSV-LOG01, 10.10.30.30/24, gateway 10.10.30.1. Use a static address or DHCP reservation. Configure authoritative lab DNS and NTP. Do not use these example addresses if they overlap your existing network.

Create an allowlist containing exact source IPs: OPNsense firewall interface address used for syslog, Mac ARM router SERVER-facing address if used, and other devices only when explicitly added.

The example uses TCP/514 on an isolated lab network. TCP syslog without TLS is not confidential or authenticated; restrict it to a private isolated segment and source allowlist. For any untrusted/inter-host network, configure TLS with certificates and hostname validation using current rsyslog GTLS documentation. Do not describe plain TCP as encrypted.

## 2. Install rsyslog and verify host identity

~~~bash
sudo apt update
sudo apt install -y rsyslog logrotate
hostnamectl
ip -br address
ip route
timedatectl status
sudo systemctl enable --now rsyslog
sudo systemctl status rsyslog --no-pager
~~~

Ensure the relay clock is synchronized. Configure the OS NTP client appropriate to the Ubuntu release and use the lab's authoritative time source where available.

## 3. Configure a restricted TCP listener

Create /etc/rsyslog.d/10-psv-input.conf:

~~~text
module(load="imtcp")
input(type="imtcp" address="10.10.30.30" port="514" ruleset="PSV-REMOTE")
~~~

Replace the bind address with the relay's actual SERVER interface address. Binding to 0.0.0.0 is not recommended because it may expose the port on management/WAN interfaces.

Create /etc/rsyslog.d/20-psv-remote-rules.conf:

~~~text
template(name="PSVRemoteLine" type="string"
         string="%timegenerated:::date-rfc3339% fromhost-ip=%fromhost-ip% hostname=%hostname% app=%programname% msg=%msg%\n")

ruleset(name="PSV-REMOTE") {
    if ($fromhost-ip == "10.10.30.1") then {
        action(type="omfile"
               file="/var/log/remote/psv-opnsense.log"
               template="PSVRemoteLine"
               fileCreateMode="0640"
               dirCreateMode="0750")
        stop
    }

    if ($fromhost-ip == "10.10.30.2") then {
        action(type="omfile"
               file="/var/log/remote/psv-mac-router.log"
               template="PSVRemoteLine"
               fileCreateMode="0640"
               dirCreateMode="0750")
        stop
    }

    # Unknown sources are not mixed into trusted source files.
    stop
}
~~~

Replace example source IPs with actual addresses observed on the wire. If OPNsense syslog source IP differs from its gateway, use the address observed at the relay. Source-IP allowlisting is a network control, not cryptographic authentication.

Create the directory and validate:

~~~bash
sudo install -d -o syslog -g adm -m 0750 /var/log/remote
sudo rsyslogd -N1
sudo systemctl restart rsyslog
sudo ss -lntp | grep ':514'
sudo journalctl -u rsyslog -n 50 --no-pager
~~~

If the installed service runs under a different account, inspect its unit and adjust ownership. Do not grant world write/read.

## 4. Restrict the relay listener at the firewall

Allow TCP/514 to 10.10.30.30 only from explicitly listed firewall/router source addresses and only on SERVER. Deny the port from WAN, home LAN, REDTEAM, DMZ and unrelated endpoints. Keep SSH management restricted to MGMT. Host firewall and upstream router rules should agree.

Verify from an allowed source:

~~~bash
nc -vz 10.10.30.30 514
~~~

A successful TCP handshake proves only reachability, not syslog parsing or file routing.

## 5. Send a controlled test message

From a Linux source with logger:

~~~bash
logger --tcp --server 10.10.30.30 --port 514 --tag PSV-RELAY-TEST "PSV relay test id=UNIQUE-TEST-ID"
~~~

Use a unique test ID and check the file matching the source-IP branch:

~~~bash
sudo grep 'UNIQUE-TEST-ID' /var/log/remote/psv-opnsense.log
sudo tail -n 20 /var/log/remote/psv-opnsense.log
~~~

Unknown sources should not be written. Add only known source IPs and repeat. Confirm hostname, source IP, application/tag, message and timestamp.

## 6. OPNsense forwarding

On OPNsense open System → Settings → Logging → Remote (menu names vary by release):
1. Add a remote target at the relay SERVER address.
2. Set TCP and port 514 to match the listener.
3. Select only required system and firewall facilities.
4. Save/apply.
5. Enable Log on the individual firewall rules used for allow/deny validation.
6. Configure Suricata EVE syslog output separately if IDS alerts are required; ordinary system syslog selection may not include EVE.
7. Generate a known allowed and blocked flow and confirm both arrive.

Do not select every facility by default; unnecessary high-volume events increase storage and hinder troubleshooting.

## 7. Mac nftables router forwarding

On the ARM64 router, first confirm nftables events appear in journald and are written to a local dedicated file. Forward only intended router firewall records to this relay and retain the local copy. Add the router's observed source IP to an exact allowlisted branch. If using TLS, configure both endpoints with a trusted CA, server certificate, correct DNS name/SAN, client-certificate policy, and renewal procedure. Test expiry/rotation.

## 8. Log rotation and disk protection

Create /etc/logrotate.d/psv-remote after verifying actual paths and rsyslog reopen behavior:

~~~text
/var/log/remote/psv-*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
~~~

Validate and dry-run:

~~~bash
sudo logrotate -d /etc/logrotate.d/psv-remote
df -h
sudo du -sh /var/log/remote
~~~

Check the installed rsyslog service's HUP behavior before production use. Set a disk alert/threshold and define behavior when the filesystem fills; never allow an unbounded log directory. Monitor queue/disk state and rsyslog health. For higher assurance, configure disk-assisted queues/retry using the exact installed release's action-queue documentation.

## 9. TLS requirement for non-isolated paths

Plain TCP/514 is only the restricted isolated-lab baseline above. If traffic crosses a shared, bridged, wireless, multi-host or otherwise untrusted network, use syslog over TLS:
- Configure rsyslog GTLS support and the imtcp input with TLS mode.
- Issue a server certificate with DNS SAN matching the name clients use.
- Install issuing CA trust on each sender.
- Require/validate client certificates where mutual authentication is selected.
- Restrict source IPs at network and host firewalls as well.
- Test trusted, untrusted, wrong-hostname and expired certificate cases.
- Document renewal, revocation and private-key permissions.

Use current rsyslog TLS documentation for exact parameter names; they are release-dependent. Do not claim TLS is active until a packet capture/connection test confirms a TLS handshake and rsyslog logs confirm the authenticated peer.

## 10. Pre-SIEM acceptance gate

- [ ] Static/reserved IP, DNS and NTP verified.
- [ ] Listener binds only to SERVER interface.
- [ ] Firewall allowlist contains exact source addresses.
- [ ] Unknown source is not written to trusted source files.
- [ ] Test syslog message reaches correct file.
- [ ] OPNsense pass/block events arrive with timestamp and rule/action context.
- [ ] Suricata EVE alert arrives if configured.
- [ ] Mac nftables events arrive if that platform is used.
- [ ] File permissions and rotation verified.
- [ ] Disk usage bounded and monitoring/alert threshold documented.
- [ ] TCP is isolated-only or TLS certificate validation is proven.
- [ ] No SIEM-specific agent installed at this stage.

## References

- [rsyslog documentation](https://www.rsyslog.com/doc/)
- [rsyslog TCP input module](https://www.rsyslog.com/doc/configuration/modules/imtcp.html)
- [rsyslog TLS documentation](https://www.rsyslog.com/doc/concepts/ns_gtls.html)
- [OPNsense remote logging](https://docs.opnsense.org/manual/settingsmenu.html)
- [Ubuntu Server documentation](https://ubuntu.com/server/docs)
