# Labs

Practical environments and experiments that connect cybersecurity concepts to observable system behaviour.

This section is documentation-led. A lab is described as **tested** only after the setup, versions, steps, and expected results have been verified. Proposed designs are reference architectures, not proof of running infrastructure.

## Featured walkthrough

- [Windows Endpoint Telemetry: Sysmon to Elastic](windows-endpoint-telemetry.md) — a safe reference design for generating, collecting, and validating a benign Sysmon process event. **Reference design; not yet lab-tested.**

## Lab areas

### Infrastructure and platform

Linux and Windows systems, virtual machines, virtual networking, storage, identity, and container fundamentals.

### Security monitoring

A defensive stack can combine endpoint telemetry (such as Sysmon and Linux audit logs), network visibility (such as Zeek or Suricata), and central analysis (such as Elastic or Wazuh). Each integration should document resource requirements and data flow.

### Offensive security

Isolated targets for reconnaissance, web application testing, vulnerability validation, and remediation verification. Testing remains within systems owned by the lab or explicitly authorised for assessment.

### Experiments

Repeatable tests for log generation, detection logic, parsing, network behaviour, platform troubleshooting, and security-control validation.

## Lab write-up standard

1. Objective, scope, and safety boundary
2. Hardware, operating system, and software versions
3. Architecture and network configuration
4. Prerequisites and implementation steps
5. Validation commands and expected results
6. Observed output, issues, and troubleshooting
7. Cleanup, rollback, and lessons learned
8. References and last-reviewed date

A diagram or proposed tool list is not proof that an environment has been deployed. Each future write-up will state its status explicitly.
