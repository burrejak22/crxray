# crxray

X-ray for Chrome extensions. Point it at an extension and get a risk report:
overprivileged permissions, broad host access, content scripts injected
everywhere, and classic code smells like `eval()` or remote script loading.

## Why

Companies maintain browser extension allowlists, and reviewing each extension
by hand is slow, boring, and inconsistent. crxray automates the first pass:
feed it an extension, get a scored findings list you can actually act on.
Security teams use it for allowlist reviews; developers use it to sanity-check
their own extensions before shipping.

## Install

```bash
npm install -g @burrejak/crxray
```

Or run from source:

```bash
git clone https://github.com/burrejak/crxray
cd crxray
npm install
```

## Usage

```bash
# unpacked extension directory
crxray ./my-extension

# packaged extension
crxray ./some-extension.crx
crxray ./some-extension.zip

# straight from the Chrome Web Store (32-char extension id)
crxray cjpalhdlnbpafiamejdnhcphjbkeiagm

# machine-readable output
crxray ./my-extension --json

# save the JSON report
crxray ./my-extension --json --out report.json
```

### CI usage

Fail the build when risk hits a threshold:

```bash
crxray ./my-extension --fail-on HIGH
```

Exit code is 1 when the band is the given level or worse
(`LOW` < `MEDIUM` < `HIGH` < `CRITICAL`).

## Example output

```
MyCoolExtension v2.1  (manifest v3, 14 files scanned)
[HIGH] risk score: 58/100 ████████████░░░░░░░░

  ▸ +40  PERM_DEBUGGER
     debugger — can attach to any tab and remote-control it
  ▸ +35  HOST_ALL_URLS
     <all_urls> — runs on literally every site
  ▸ +25  CODE_EVAL
     eval() — the classic remote-code vector (first seen in background.js)
```

## How scoring works

Every finding carries a weight based on how much damage that capability
enables. Weights are opinionated, not scientific — the point is ranking and
triage, not a certification. Totals are capped at 100:

| Band     | Score  | Meaning                              |
|----------|--------|--------------------------------------|
| LOW      | 0–19   | boring in a good way                 |
| MEDIUM   | 20–44  | worth a look                         |
| HIGH     | 45–69  | needs justification to allowlist     |
| CRITICAL | 70–100 | do not install until this is explained |

What gets checked:

- **Permissions** — `debugger`, `management`, `nativeMessaging`, `cookies`,
  `history`, `webRequestBlocking`, etc., each weighted by abuse potential.
- **Host permissions** — `<all_urls>`, full wildcards, plaintext `http://`.
- **Content scripts** — injected on every page, running in iframes, running
  before page load.
- **Code patterns** — `eval()`, `new Function()`, remote `.js` references,
  `fetch()` piped into `innerHTML`, opaque WebAssembly blobs.
- **Permission combos** — permissions that are fine alone but dangerous
  together (traffic interception, data exfiltration, tab hijacking).
- **Hardcoded secrets** — AWS keys, GitHub tokens, Google API keys, private
  keys, and generic api_key/secret assignments sitting in the bundle.
- **Web-accessible resources** — extension resources exposed to every site
  (fingerprinting and injection surface).
- **Manifest metadata** — manifest v2 (deprecated), custom `update_url`
  (self-updating outside the store), wide-open `externally_connectable`.

## Limitations

- Static analysis only. It reads the code, it doesn't run it. Obfuscated or
  dynamically constructed payloads can slip past the pattern checks.
- Scores are triage heuristics. A HIGH score means "a human should look",
  not "this is malware".
- Web Store downloads use Google's update API; if Google changes it, the
  extension-id shortcut breaks (path/zip/crx inputs keep working).

## Contributing

Issues and PRs welcome. Keep it dependency-light and keep the CLI fast.
