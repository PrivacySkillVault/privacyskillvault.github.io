# Windows Endpoint Telemetry: Sysmon to Elastic

<badge color="warning">Reference design — not yet lab-tested</badge>

This walkthrough describes a safe, reproducible design for collecting Windows process-creation telemetry and reviewing it in Elastic. It is a build plan, not evidence that this environment has been deployed or tested. Record the exact Windows, Sysmon, Elastic Agent, Elasticsearch, and Kibana versions before marking it tested.

## Objective

Generate one benign process event on an isolated Windows virtual machine, confirm that Sysmon records it, collect the event with Elastic, and verify that the event can be searched and interpreted.

**Success criteria**

1. A controlled process launch produces a Sysmon Process Create event (Event ID 1).
2. The event is visible in the local Sysmon Operational log.
3. The configured collection agent forwards the event to the expected Elastic data stream.
4. The event contains enough context to identify the process and its parent.
5. The write-up records any missing fields, collection delay, and configuration limitations.

## Scope and safety

- Use a Windows VM that you own or are explicitly authorised to administer.
- Use Notepad as the benign test process. Do not use malware, exploit code, credential dumping, persistence payloads, or live suspicious indicators.
- Prefer a host-only or otherwise restricted virtual network. Permit only the management and telemetry connectivity required by your lab.
- Do not connect this exercise to production endpoints or production SIEM data.
- Do not paste real user, customer, or employer telemetry into public tools.

## Reference architecture

```text
Windows test VM
  └─ Sysmon service
       └─ Microsoft-Windows-Sysmon/Operational
            └─ Elastic Agent (Windows integration)
                 └─ Elasticsearch
                      └─ Kibana Discover
```

The Elastic Windows integration documents collection of Windows-specific channels including Sysmon and PowerShell. The Sysmon data stream is named `windows.sysmon_operational` in the integration documentation. Confirm the actual data stream and field mappings in your own version before using saved queries.

## Prerequisites

- A supported Windows 10 or Windows 11 VM with administrative access. On Windows 11, check whether the built-in Sysmon optional feature is available in your edition/build.
- Sysmon downloaded from Microsoft's official Sysinternals page.
- An Elastic environment with a compatible Elastic Agent and Windows integration, or an equivalent approved log collector.
- Sufficient disk space for the VM and a snapshot taken before configuration.
- A written record of versions, VM network mode, host name, and collection configuration.

Official references:

- [Microsoft: Enable and configure Sysmon in Windows](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [Microsoft Sysmon download and usage](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Elastic Windows integration](https://www.elastic.co/docs/reference/integrations/windows)

## Procedure

### 1. Prepare the endpoint

1. Create or select an isolated Windows VM.
2. Apply the updates required for the lab and record the OS build.
3. Take a VM snapshot.
4. Confirm the VM can reach only the required management and telemetry endpoints.
5. Record the local time zone. Sysmon event timestamps are recorded in UTC.

### 2. Install and verify Sysmon

Windows 11 now offers Sysmon as a built-in optional feature, while the standalone Sysinternals download remains available. Choose one installation method appropriate to the VM and Windows version; do not install the built-in feature and standalone package on top of one another.

1. Check whether Sysmon is already installed before making changes:

```powershell
Get-Service sysmon*
```

2. For Windows 11, review Microsoft's current instructions for enabling the built-in optional feature. For Windows 10, or where you deliberately choose the standalone package, download Sysmon from the official Microsoft Sysinternals page. Verify the download source and publisher.
3. Review the current Microsoft usage instructions before installation; command-line options can change between Sysmon releases.
4. Install or enable Sysmon with an approved configuration. For this first exercise, ensure Process Create telemetry is enabled.
5. Open Event Viewer and navigate to **Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**.
6. Confirm the channel is present, Sysmon is running, and new events are being written.

Sysmon Event ID 1 records process creation, including process and parent-process context. Network connection events (Event ID 3) are disabled by default, so do not expect them unless you deliberately enable them in the configuration.

### 3. Generate a benign event

Open PowerShell in the test VM and run:

```powershell
Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -PassThru |
    Select-Object Id, ProcessName
```

Close Notepad normally after confirming it started.

In Event Viewer, inspect the newest Sysmon Process Create event. Confirm that the image, process ID, command line, parent process, user, and timestamp fields are populated where available. The exact values depend on the VM and Sysmon configuration.

You can also inspect recent events with PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 1
} -MaxEvents 10 |
    Select-Object TimeCreated, Id, ProviderName, Message
```

### 4. Configure collection

In Elastic Fleet, enrol an Elastic Agent on the Windows VM and add the Windows integration according to the official integration guide. Enable the Sysmon Operational channel/data stream.

Do not assume that adding the integration proves collection is working. Check agent health, integration policy, permissions, data stream creation, and the arrival of a new event generated after the policy was applied.

If you use a different SIEM or collector, document the equivalent source channel, collection method, destination, parsing stage, and field mapping.

### 5. Search and verify

In Kibana Discover, select the relevant Sysmon data view and search for the test process. A starting KQL example is:

```kql
event.dataset : "windows.sysmon_operational"
and event.code : "1"
and process.name : "notepad.exe"
```

The integration's field mappings and dataset names can vary by version and configuration. If the query returns no results, inspect the raw event and the data view before changing the query. Do not interpret a failed query as proof that no event was generated.

For the matching event, record:

- `@timestamp` and the source event time
- `event.dataset` and `event.code`
- `host.name`
- `process.name`, `process.executable`, and `process.command_line`
- `process.pid` and `process.entity_id`, if present
- `process.parent.name`, `process.parent.executable`, and parent process ID, if present
- `user.name`, if present
- The time at which the event became searchable

### 6. Validate the collection path

| Check | Expected evidence | If it fails |
|---|---|---|
| Sysmon installed | Sysmon service and Operational channel exist | Review installation and service status |
| Event generated | Event ID 1 for the Notepad process | Check Sysmon configuration and event time |
| Agent healthy | Agent is enrolled and policy is applied | Review agent status, permissions, and connectivity |
| Data received | New Sysmon document appears in the expected data stream | Check integration channel, agent logs, and ingest errors |
| Fields usable | Process and host fields are searchable | Inspect the raw event and parsing/mapping |
| Timeline consistent | Source time precedes or matches ingestion time | Check time zones, clock synchronisation, and pipeline delay |

A local event with no corresponding SIEM document indicates a collection or ingestion problem, not a detection failure. A document with missing fields indicates a parsing, mapping, or source-configuration issue that should be diagnosed separately.

## Troubleshooting checklist

- Verify the Sysmon service is running and the Operational channel is enabled.
- Confirm Event ID 1 is not excluded by the Sysmon configuration.
- Generate a new event after the collector policy is active; do not rely only on older events.
- Confirm the Elastic Agent policy includes the Windows integration and Sysmon channel.
- Check agent health, network reachability, permissions, ingest pipeline errors, and data-stream naming.
- Compare the raw event with the parsed document before changing field names in a query.
- Check endpoint and SIEM clock synchronisation and compare source event time with ingestion time.

## Cleanup

1. Close the test process.
2. If Sysmon was installed only for this exercise, remove it using the uninstall procedure documented by Microsoft.
3. Remove or unenrol the test agent only if it is no longer required.
4. Retain or delete lab data according to your lab retention policy.
5. Revert the VM snapshot if you want to return to the original state.

## Evidence record

Before changing the status to **Lab-tested**, attach or record:

- Windows edition/build and VM platform
- Sysmon version and configuration hash or version
- Elastic Agent, integration, Elasticsearch, and Kibana versions
- Sanitised screenshot or export of the local Event ID 1
- Sanitised SIEM document showing the same process event
- Query used and exact fields observed
- Collection delay and any troubleshooting performed
- Cleanup result and date last verified

**Current status:** Reference design only. No execution results are claimed by this page.

## Further reading

- [Microsoft: Understanding Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Elastic: Windows integration](https://www.elastic.co/docs/reference/integrations/windows)
