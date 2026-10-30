# Synthetic Detection Fixtures

These four JSON Lines records are constructed test inputs. They are not exported Windows event records, and they do not represent real systems, users, or incidents. Use them to document intended match/no-match behaviour, then test the rule against genuine raw event samples from an isolated lab with the relevant audit settings enabled.

Fields are deliberately simplified. They must not be treated as a replacement for the original Sysmon or Windows Security event XML.

- `PSV-DET-001-POS`: PowerShell process with encoded-command argument; expected match.
- `PSV-DET-001-NEG`: PowerShell process without encoded-command argument; expected no-match.
- `PSV-DET-002-POS`: Event 4732 targeting the built-in Administrators SID; expected match.
- `PSV-DET-002-NEG`: Event 4732 targeting the built-in Users SID; expected no-match.

