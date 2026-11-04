# Secure Share — release validation checklist

This feature is separate from the DFIR **Secure Evidence Share** passphrase-based encrypt/decrypt utility. Do not rename or replace that existing tool.

## Static checks
- [ ] Page is served at `/secure-share/` over HTTPS.
- [ ] The Tools sidebar contains **Secure Share (Live Transfer)** under DFIR & Forensics.
- [ ] Selecting it opens the standalone transfer page.
- [ ] Existing **Secure Evidence Share** still opens the original encrypt/decrypt workflow.
- [ ] No new API endpoint, file upload, or server-side content storage is introduced.
- [ ] PeerJS is loaded from the pinned `1.5.5` CDN path.

## Required real-browser tests before production approval
Use two separate devices and current Chrome/Firefox/Safari versions. Keep the sender online.

1. Text: send a harmless marker string. Confirm recipient receives the exact text in a downloaded file.
2. Small file: transfer a harmless 500 KB test file. Compare SHA-256 hashes before and after.
3. Larger file: test 5–9 MB. Confirm chunk acknowledgements complete and the final hash matches.
4. Empty input and no input: both must be rejected without creating a session.
5. Over limit: a file larger than 10 MB must be rejected before creating a peer session.
6. Sender rejects recipient: no payload must be transferred.
7. Second recipient: after one recipient is approved, another connection must be rejected.
8. Expiry: wait 10 minutes; the session must close and a new link must be required.
9. Interrupted network: stop network during transfer; no successful completion or usable partial download may be shown.
10. Reconnect: reload or reconnect with the old link after completion; it must fail.
11. Different networks: test office/home Wi-Fi against a mobile hotspot. Direct WebRTC may fail on restrictive NAT/firewalls because this release has no TURN relay; record this as a connectivity limitation rather than silently claiming success.
12. Browser console: check for uncaught errors, unhandled promise rejections, and repeated event handlers.

## Security notes
- The complete share URL is a bearer secret because its fragment contains the decryption key. Never paste a real link into tickets, chat transcripts, analytics, or screenshots.
- PeerJS signalling exposes connection metadata to the signalling provider. The file payload is sent over the WebRTC data channel and encrypted in the browser.
- A recipient can retain or redistribute a downloaded file. The browser cannot enforce downstream controls.
- This feature is not a replacement for an organisation-approved managed evidence-transfer service.
- Do not use production or regulated evidence during validation; use synthetic test files only.

Record browser versions, OS versions, network types, file sizes, test result, and SHA-256 comparison for each run. Production approval requires successful separate-device tests; automated build checks alone do not prove WebRTC interoperability.
