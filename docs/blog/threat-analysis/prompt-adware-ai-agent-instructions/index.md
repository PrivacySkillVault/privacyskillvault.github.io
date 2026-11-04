# Prompt Adware: When an AI Jailbreak Quietly Rewrites an Agent’s Trust Boundary

<small>THREAT ANALYSIS · AI SECURITY · 04 NOV 2026 · 7 MIN READ</small>

<p class="psv-article-breadcrumb"><a href="../">← Threat Analysis</a><span> / </span><a href="../../">Cyber Journal</a></p>

AI-agent security is not limited to the model itself. Prompts, Skills, plugins and configuration files can shape what an agent does long after an installation. Check Point Research's November 3, 2026 investigation into a Codex jailbreak bundle called **Haiou** illustrates how those trusted inputs can be abused for commercial influence.

The researchers coined the term **prompt adware** for a package that persistently changes an agent's trusted instructions so later responses promote an external AI gateway. The finding is not evidence that the advertised gateway itself is malicious, nor does it establish that the package author created it for cybercrime. The security issue is the hidden, persistent change to agent behaviour.

## What researchers found

Haiou is presented as a local enhancement and security-research configuration bundle for OpenAI Codex. Check Point says it uses prompt-injection approaches such as role-play, refusal suppression and reframing security requests as Capture-the-Flag exercises. It also installs security-oriented Skills for activities such as penetration testing and reverse engineering.

The more unusual behaviour is its modification of global agent instruction files. A greeting or activation phrase can cause the agent to return a promotional message for a third-party, OpenAI-compatible LLM gateway. Because the instruction persists in the agent configuration, the behaviour can appear in later conversations rather than only during the initial setup.

Check Point also observed the bundle on infrastructure associated with a threat actor using Cobalt Strike and other dual-use tools. That context demonstrates that the bundle was present in a threat actor's environment; it does **not** prove that the bundle's author was the threat actor or that every user of the bundle is malicious.

## Why this matters to security teams

Traditional endpoint controls are designed to identify executable files, processes, persistence mechanisms and network activity. Prompt adware adds another layer: a seemingly ordinary configuration change can alter an AI assistant's recommendations and responses without installing a conventional executable payload.

The same mechanism could potentially be adapted to steer users toward selected vendors, bias technical advice, suppress warnings or encourage unsafe actions. Those are risk scenarios, not behaviours that Check Point demonstrated in every case.

The risk becomes more significant when agents can read source code, access internal documentation, call tools or interact with production systems. A compromised instruction layer could influence how an agent uses those permissions.

## Investigation and defensive checklist

| Area | What to validate |
|---|---|
| Agent inventory | Identify approved AI coding agents and their installation sources |
| Configuration integrity | Baseline global instruction files, project rules and agent settings |
| Skills and extensions | Review provenance, permissions, contents and update history |
| Persistence | Alert on unexpected changes to agent configuration directories |
| Egress | Review whether agents communicate with unapproved gateways or destinations |
| Access control | Limit agent access to secrets, production credentials and sensitive repositories |
| Change governance | Require review before installing third-party Skills or configuration bundles |

For incident response, preserve the original configuration files and package, record hashes and timestamps, identify which agent profiles loaded the changes, and determine whether any sensitive files or tools were accessible during affected sessions. Do not assume that removing the visible advertisement alone reverses every change made by a third-party bundle.

## Practical takeaway

Treat an AI agent's instruction files as security-relevant configuration. Apply the same discipline used for scripts and extensions: trusted sources, change review, least privilege, integrity monitoring and a clear removal process.

The key question is no longer only *which model is running?* It is also *who can change the instructions and components that influence the model's behaviour?*

## References

- [Check Point Research — Free the Model, Sell the Gateway: Prompt Adware hidden in Jailbreak Bundles](https://research.checkpoint.com/2026/free-the-model-sell-the-gateway-prompt-adware-hidden-in-jailbreak-bundles/) — primary technical research, November 3, 2026.
- [The Hacker News — Researchers Uncover Prompt Adware Hidden in OpenAI Codex Jailbreak Toolkit](https://thehackernews.com/2026/11/researchers-uncover-prompt-adware.html) — secondary reporting, November 4, 2026.

*PSV analysis based on the cited public research. The article distinguishes observed behaviour from potential downstream abuse and does not claim independent reproduction.*
