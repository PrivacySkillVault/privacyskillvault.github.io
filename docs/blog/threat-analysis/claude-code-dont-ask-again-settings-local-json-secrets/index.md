# Claude Code's “Don't Ask Again” Setting Can Expose Secrets in Public Git Repositories

<small>THREAT ANALYSIS · AI / DEVELOPER SECURITY · 07 NOV 2026 · 9 MIN READ</small>

<p class="psv-article-breadcrumb"><a href="../">← Threat Analysis</a><span> / </span><a href="../../">Cyber Journal</a></p>

A convenience feature in Claude Code can create an unexpected secrets-management risk. When a developer approves a shell command and selects **“Yes, and don't ask again,”** Claude Code records a permission rule in the project's local settings file, **`.claude/settings.local.json`**. If the approved command contains a password, API token or other credential as literal text, that value can be retained in the rule.

Security company Apiiro reported finding **1,122 public copies** of this file containing at least one secret in its GitHub research. The finding is a real exposure risk, but it needs careful interpretation: the researchers did not test all credentials to determine whether they remained valid, and a public file containing a secret is not by itself proof that an attacker used it.

## What does “Don't Ask Again” save?

Claude Code supports permission rules that allow or deny tool actions. Its official documentation explains that when a user chooses “Yes, and don't ask again” for a Bash command, the approval is saved as an `allow` rule in `.claude/settings.local.json`.

For example, a developer might approve a one-off command containing an inline database password or access token. If the saved rule records the command literally, the credential may become part of the JSON settings file. The danger is not that every permission rule contains a secret; it is that command lines sometimes contain secrets that should never be written into project configuration or source control.

Claude Code's documentation also describes an important protection: when it creates this local settings file in a Git repository, it adds the path to the user's **global Git excludes** file. That normally keeps the file untracked on that user's machine. However, global excludes are local to that environment. They are not the same as a repository's committed `.gitignore`, and they do not remove a file that was already tracked or committed. If a user creates the file manually before Claude Code has added the global exclusion, the user must add it to `.gitignore` themselves.

## What did Apiiro report?

The Hacker News reported the following figures from Apiiro's research:

- **104,185** copies of `.claude/settings.local.json` were identified across **103,617 public GitHub repositories**.
- **1,122 files**, approximately **1.1%**, were reported to contain at least one secret.
- Those current copies contained **1,379 distinct credentials**.
- The reported categories included 379 database passwords, 43 SSH logins for public servers, 42 GitHub, GitLab or npm tokens, and 23 AWS keys.
- Apiiro said one organisation it notified confirmed that an exposed key had been live.

Apiiro's broader analysis also included older versions in Git history, forks, the shared `.claude/settings.json` file and saved agent transcripts. That wider scope was reported as **2,539 secrets across 1,994 repositories**. It is a separate, broader count and should not be added to the 1,379 credentials found in current local-settings copies.

There are limitations. Apiiro did not attempt to authenticate with every credential, so the research does not establish how many remained active or were misused. The figures are the research firm's findings as reported by The Hacker News; they should be attributed to Apiiro rather than presented as an independently reproduced GitHub-wide measurement.

## Why can a local exclusion fail to protect a repository?

Git has several ways to ignore files:

- **Global excludes:** apply to repositories on one user's machine. Claude Code documents adding `**/.claude/settings.local.json` to this exclusion list when it creates the file.
- **Repository `.gitignore`:** is committed with the project and helps protect every contributor's working copy.
- **Git tracking and history:** ignore rules do not untrack a file that has already been committed. Deleting it in a later commit does not remove the previous versions from Git history, existing clones or forks.

This distinction explains how a local settings file can still become public. A developer may commit it before the global exclusion is configured, force-add it, use a different machine, or work in a repository where the file is already tracked. Once a credential reaches a public repository, assume it may have been copied even if the file is later deleted or the repository is made private.

## How to check your repositories

Start by checking whether the file is tracked in the current repository:

```sh
git ls-files | grep -E '(^|/)\.claude/settings\.local\.json$'
```

Then inspect Git history across local branches and references:

```sh
git log --all --name-only --pretty=format: -- \
  .claude/settings.local.json
```

Search for both local and shared settings files in the repository:

```sh
find . -path '*/.claude/settings.local.json' -o \
       -path '*/.claude/settings.json'
```

Review any discovered files securely. Look for literal passwords, tokens, connection strings, `Authorization` headers, command-line flags such as `--password` or `--token`, and inline environment assignments such as `DB_PASSWORD=value`.

These commands identify candidate files; they do not establish whether a credential is valid or whether it has been accessed by someone else. Avoid copying discovered secrets into tickets, chat messages or terminal history while investigating.

## What should developers and security teams do?

### 1. Rotate exposed credentials first

If a secret was committed to a public repository, treat it as compromised. Revoke or rotate the credential at its issuing service before focusing on file cleanup. Prioritise database credentials, cloud access keys, source-control tokens, package-registry tokens and SSH credentials that permit access to public systems.

Do not wait for evidence of misuse before rotating a credential that was publicly exposed. Check provider audit logs and access history for suspicious use, but remember that absence of a logged event does not prove that a credential was never copied.

### 2. Stop tracking the local settings file

If the file is currently tracked, remove it from the Git index without deleting the developer's local copy:

```sh
git rm --cached .claude/settings.local.json
```

Add a repository-level ignore rule:

```gitignore
.claude/settings.local.json
```

Then commit the ignore rule. This is additional protection for the project; it does not replace the user's global exclusion or remove historical copies.

### 3. Review Git history and forks

Search all branches and tags, not only the current working tree. If credentials were committed, follow your organisation's process for purging sensitive data from history. Coordinate any history rewrite with contributors because existing clones and forks may still contain the old object. Credential rotation remains essential even after history cleanup.

### 4. Stop placing secrets directly in commands

Prefer retrieving credentials from a secrets manager or a protected environment variable at runtime rather than typing the secret as a literal command argument. Be aware that environment variables and process arguments have their own exposure considerations; use the method approved by your platform and operating-system security guidance.

For recurring approvals, use narrowly scoped command patterns where appropriate, and review the resulting allow rules before sharing or committing project configuration. A broad permission pattern can create a different security risk, so do not trade secret exposure for excessive command permissions.

### 5. Add scanning that checks history

Include `.claude/` and other AI-agent configuration locations in secret-scanning policies. Run scanners in pre-commit and CI, and scan repository history where feasible. Apiiro's reported comparison found that common scanners did not identify every file it classified as containing secrets, so use more than one detection method and include contextual review.

### 6. Set organisational guardrails

Teams using AI coding assistants should define where secrets may be stored, which commands agents may run, and how permission rules are reviewed. Managed settings and policy controls can restrict agent access to sensitive files, but they do not eliminate the need to keep credentials out of command strings and source control.

## What this means for SOC and incident response

Treat a discovered credential in a public repository as a potential exposure incident. Build a timeline around the first commit containing the secret, repository visibility, forks and mirrors, credential lifetime, and the actions permitted by the credential.

Correlate provider-side authentication logs, source IPs, user agents, API activity, database access, cloud audit events and source-control activity. Distinguish three separate findings:

1. **Exposure:** a secret was present in a repository or its history.
2. **Validity:** the secret was still accepted by the provider during the exposure window.
3. **Misuse:** evidence shows that someone used the credential without authorisation.

These are not interchangeable. The research establishes that secrets were exposed in the examined public files; it does not establish misuse of every credential.

## Key takeaways

- Claude Code documents saving “Yes, and don't ask again” Bash approvals as allow rules in `.claude/settings.local.json`.
- A literal credential embedded in an approved command can therefore be retained in a settings rule and exposed if the file is committed.
- Claude Code normally adds the local file to global Git excludes when it creates it, but global excludes do not clean tracked files or Git history.
- Apiiro reported 1,122 public copies containing secrets; it did not test every credential, so exposure must not be described as confirmed account compromise.
- Rotate first, then untrack and ignore the file, review history and forks, and add secret scanning that includes AI-agent configuration.

## References

- [The Hacker News — Claude Code's “Don't Ask Again” File Exposes Passwords and Keys in 1,122 Public Copies on GitHub](https://thehackernews.com/2026/11/claude-codes-dont-ask-again-file.html) — November 7, 2026 reporting on Apiiro's research.
- [Anthropic — Claude Code settings files and precedence](https://code.claude.com/docs/en/settings) — official documentation for local settings, permission approvals and global Git excludes.
- [Apiiro — research on Claude Code settings and exposed secrets](https://apiiro.com/) — research publisher; consult its original report for methodology and updates.
- [Git documentation — gitignore](https://git-scm.com/docs/gitignore) — explains per-repository and global ignore behaviour.
- [GitHub Docs — Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) — history-removal considerations and limitations.
