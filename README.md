# crxray

X-ray for Chrome extensions. Point it at one, get a risk report. Overprivileged permissions, broad host access, content scripts injected everywhere, `eval()` and remote script loading, hardcoded secrets.

## Why

Browser extensions run with absurd power. They see every tab, read your DOM, hook requests, and ship updates through the Web Store whenever the author pushes one. The question that matters is whether a given extension's capabilities actually match what it says it does. crxray answers that in a few seconds instead of an afternoon of code review.

## Install

```bash
npm install -g @burrejak/crxray
```

From source:

```bash
git clone https://github.com/burrejak22/crxray
cd crxray
npm install
```

## Use

```bash
crxray ./my-extension                              # unpacked folder
crxray ./some-extension.crx                        # packaged
crxray ./some-extension.zip
crxray cjpalhdlnbpafiamejdnhcphjbkeiagm            # straight from the Web Store
crxray ./my-extension --json
crxray ./my-extension --json --out report.json
```

### CI

```bash
crxray ./my-extension --fail-on HIGH
```

Exit 1 when the risk band hits the threshold (`LOW` < `MEDIUM` < `HIGH` < `CRITICAL`).

## Example output

```
MyCoolExtension v2.1  (manifest v3, 14 files scanned)
[HIGH] risk score: 58/100 ████████████░░░░░░░░

  ▸ +40  PERM_DEBUGGER
     debugger. can attach to any tab and remote-control it
  ▸ +35  HOST_ALL_URLS
     <all_urls>. runs on literally every site
  ▸ +25  CODE_EVAL
     eval(). the classic remote-code vector (first seen in background.js)
```

## Scoring

Every finding has a weight for how much damage that capability enables. Weights are opinionated, not scientific. The point is triage, not certification. Totals cap at 100.

| Band     | Score  | Meaning                              |
|----------|--------|--------------------------------------|
| LOW      | 0 to 19   | boring in a good way                 |
| MEDIUM   | 20 to 44  | worth a look                         |
| HIGH     | 45 to 69  | needs justification to allowlist     |
| CRITICAL | 70 to 100 | do not install until this is explained |

What gets checked:

- **Permissions**. `debugger`, `management`, `nativeMessaging`, `cookies`, `history`, `webRequestBlocking`, etc., each weighted by abuse potential.
- **Host permissions**. `<all_urls>`, full wildcards, plaintext `http://`.
- **Content scripts**. Injected on every page, running in iframes, running before page load.
- **Code patterns**. `eval()`, `new Function()`, remote `.js` references, `fetch()` piped into `innerHTML`, opaque WebAssembly blobs.
- **Permission combos**. Fine alone, dangerous together. Traffic interception, data exfiltration, tab hijacking.
- **Hardcoded secrets**. AWS keys, GitHub tokens, Google API keys, private keys, and generic `api_key` / `secret` assignments sitting in the bundle.
- **Web-accessible resources**. Extension resources exposed to every site (fingerprinting and injection surface).
- **Manifest metadata**. Manifest v2 (deprecated), custom `update_url` (self-updating outside the store), wide-open `externally_connectable`.

## Limitations

Static analysis only. It reads the code, it doesn't run it. Obfuscated or dynamically constructed payloads can slip past the pattern checks. Scores are triage heuristics. HIGH means "a human should look", not "this is malware". Web Store downloads go through Google's update API; if Google changes it, the extension-id shortcut breaks (path/zip/crx inputs keep working).

## Contributing

Issues and PRs welcome. Keep it dependency-light and keep the CLI fast.
