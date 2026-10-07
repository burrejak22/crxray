// the whole brain of the operation — what we look for and how much we care

// permission -> damage potential. scores are vibes-based but directionally right.
const PERMISSION_RISKS = {
  debugger:           { score: 40, note: "can attach to any tab and remote-control it" },
  management:         { score: 30, note: "can install, disable, or remove other extensions" },
  nativeMessaging:    { score: 30, note: "talks to native binaries, escapes the browser sandbox" },
  proxy:              { score: 25, note: "reroutes all browser traffic wherever it wants" },
  history:            { score: 25, note: "reads your entire browsing history" },
  cookies:            { score: 25, note: "reads and writes cookies, session theft 101" },
  webRequestBlocking: { score: 25, note: "can silently modify requests and responses" },
  browsingData:       { score: 20, note: "can wipe history, cookies, cache" },
  webRequest:         { score: 20, note: "passively observes traffic on matched hosts" },
  tabs:               { score: 20, note: "sees URLs and titles of every open tab" },
  topSites:           { score: 15, note: "reads your most-visited sites" },
  downloads:          { score: 15, note: "can pull files down with barely a prompt" },
  geolocation:        { score: 15, note: "precise location access" },
  clipboardRead:      { score: 15, note: "reads whatever you copy, passwords included" },
  privacy:            { score: 15, note: "can flip browser privacy settings" },
  identity:           { score: 10, note: "OAuth flows, token theft if abused" },
  scripting:          { score: 10, note: "injects code into pages, fine when hosts are tight" },
  activeTab:          { score: 5,  note: "one-time access on user click, standard" },
  storage:            { score: 5,  note: "local key/value storage" },
  alarms:             { score: 5,  note: "just timers" },
  contextMenus:       { score: 5,  note: "right-click menu entries" },
  notifications:      { score: 5,  note: "desktop popups" },
  clipboardWrite:     { score: 5,  note: "writes to clipboard, mildly annoying at worst" },
  unlimitedStorage:   { score: 5,  note: "bigger local storage quota" },
  idle:               { score: 5,  note: "detects when you're afk" },
};

function checkPermissions(permissions = []) {
  const out = [];
  for (const p of permissions) {
    const known = PERMISSION_RISKS[p];
    if (known) {
      out.push({ code: `PERM_${p.toUpperCase()}`, score: known.score, detail: `${p} — ${known.note}` });
    } else {
      // not in the catalog, probably fine, but say so out loud
      out.push({ code: "PERM_UNKNOWN", score: 3, detail: `${p} — not in our catalog, eyeball it` });
    }
  }
  return out;
}

function checkHostPermissions(hosts = []) {
  const out = [];
  for (const h of hosts) {
    if (h === "<all_urls>") {
      out.push({ code: "HOST_ALL_URLS", score: 35, detail: "<all_urls> — runs on literally every site" });
      continue;
    }
    // only the host part matters for broadness, path wildcards like /* are normal
    const hostPart = h.replace(/^[a-z*]+:\/\//i, "").split("/")[0];
    if (hostPart === "*" || hostPart === "*.*") {
      out.push({ code: "HOST_WILDCARD_ALL", score: 30, detail: `${h} — every host on the internet` });
    } else if (hostPart.startsWith("*.")) {
      out.push({ code: "HOST_WILDCARD_SUBDOMAIN", score: 15, detail: `${h} — all subdomains, pretty broad` });
    } else if (/^http:\/\//i.test(h)) {
      out.push({ code: "HOST_PLAINTEXT", score: 10, detail: `${h} — plaintext http, traffic visible on the wire` });
    }
    // tight https host? that's the dream, no finding
  }
  return out;
}

function checkContentScripts(scripts = []) {
  const out = [];
  for (const cs of scripts) {
    const matches = cs.matches || [];
    if (matches.includes("<all_urls>")) {
      out.push({ code: "CS_ALL_URLS", score: 20, detail: "content script injected into every page" });
    } else if (matches.some((m) => m.replace(/^[a-z*]+:\/\//i, "").split("/")[0].includes("*"))) {
      out.push({ code: "CS_BROAD_MATCH", score: 10, detail: `content script matches broad pattern: ${matches.join(", ")}` });
    }
    if (cs.all_frames) {
      out.push({ code: "CS_ALL_FRAMES", score: 5, detail: "content script also runs inside iframes" });
    }
    if (cs.run_at === "document_start") {
      out.push({ code: "CS_EARLY_RUN", score: 5, detail: "content script runs before the page even loads" });
    }
  }
  return out;
}

// static code smells. dumb regexes, but they catch the classics.
const CODE_CHECKS = [
  { code: "CODE_EVAL", score: 25, detail: "eval() — the classic remote-code vector",
    test: (src) => /\beval\s*\(/.test(src) },
  { code: "CODE_NEW_FUNCTION", score: 20, detail: "new Function() — eval in a trenchcoat",
    test: (src) => /new\s+Function\s*\(/.test(src) },
  { code: "CODE_REMOTE_JS", score: 15, detail: "references a remote .js file — where does it actually load from?",
    test: (src) => /https?:\/\/[^\s'")]+?\.js/i.test(src) },
  { code: "CODE_FETCH_TO_DOM", score: 15, detail: "fetch() and innerHTML in the same file — injection-prone combo",
    test: (src) => src.includes("fetch(") && src.includes("innerHTML") },
  { code: "CODE_WASM_BLOB", score: 10, detail: "ships WebAssembly — opaque binary, can't easily audit what it does",
    test: (src, name) => name.endsWith(".wasm") },
];

function checkCodeFiles(files) {
  // files: [{ name, content }]. one finding per pattern, don't spam per file.
  const out = [];
  const seen = new Set();
  for (const f of files) {
    for (const c of CODE_CHECKS) {
      if (seen.has(c.code)) continue;
      let hit = false;
      try { hit = c.test(f.content || "", f.name); } catch { hit = false; }
      if (hit) {
        seen.add(c.code);
        out.push({ code: c.code, score: c.score, detail: `${c.detail} (first seen in ${f.name})` });
      }
    }
  }
  return out;
}

function checkManifestMeta(manifest) {
  const out = [];
  if (manifest.manifest_version === 2) {
    out.push({ code: "META_MV2", score: 5, detail: "manifest v2 — deprecated, migrate to v3 when you can" });
  }
  if (manifest.update_url && !manifest.update_url.includes("google.com")) {
    out.push({ code: "META_CUSTOM_UPDATE", score: 20, detail: `custom update_url (${manifest.update_url}) — self-updating outside the web store` });
  }
  const ec = manifest.externally_connectable;
  if (ec && ec.matches && ec.matches.some((m) => m === "<all_urls>" || m === "*://*/*")) {
    out.push({ code: "META_EXT_CONNECTABLE", score: 15, detail: "externally_connectable open to all urls — any site can message it" });
  }
  const csp = typeof manifest.content_security_policy === "string"
    ? manifest.content_security_policy
    : manifest.content_security_policy && manifest.content_security_policy.extension_pages;
  if (csp && /https?:\/\//.test(csp)) {
    out.push({ code: "META_REMOTE_CSP", score: 20, detail: "content security policy allows remote hosts — remote code risk" });
  }
  return out;
}

function bandFor(score) {
  if (score >= 70) return "CRITICAL";
  if (score >= 45) return "HIGH";
  if (score >= 20) return "MEDIUM";
  return "LOW";
}

// dangerous permission combos — the whole is worse than the parts
const PERM_COMBOS = [
  {
    code: "COMBO_TRAFFIC_INTERCEPT",
    score: 30,
    detail: "tabs/history/cookies + webRequestBlocking + broad host access — can silently read and rewrite all browsing traffic",
    needs: { any: [["tabs", "history", "cookies"]], all: ["webRequestBlocking"], hosts: "broad" },
  },
  {
    code: "COMBO_DATA_EXFIL",
    score: 25,
    detail: "cookies/history + broad host access — can siphon sessions and history off to anywhere",
    needs: { any: [["cookies", "history"]], hosts: "broad" },
  },
  {
    code: "COMBO_TAB_HIJACK",
    score: 20,
    detail: "debugger/management + broad host access — full remote control over tabs or other extensions",
    needs: { any: [["debugger", "management"]], hosts: "broad" },
  },
];

function isBroadHost(h) {
  if (h === "<all_urls>") return true;
  const hostPart = h.replace(/^[a-z*]+:\/\//i, "").split("/")[0];
  return hostPart === "*" || hostPart === "*.*" || hostPart.startsWith("*.");
}

function checkPermissionCombos(named = [], hosts = []) {
  const out = [];
  const broad = (hosts || []).some(isBroadHost);
  for (const combo of PERM_COMBOS) {
    const anyOk = !combo.needs.any || combo.needs.any.every((group) => group.some((p) => named.includes(p)));
    const allOk = !combo.needs.all || combo.needs.all.every((p) => named.includes(p));
    const hostOk = !combo.needs.hosts || (combo.needs.hosts === "broad" && broad);
    if (anyOk && allOk && hostOk) {
      out.push({ code: combo.code, score: combo.score, detail: combo.detail });
    }
  }
  return out;
}

// hardcoded secrets — extensions ship their keys in the bundle constantly
const SECRET_PATTERNS = [
  { code: "SECRET_AWS_KEY", score: 30, detail: "hardcoded AWS access key",
    re: /\bAKIA[0-9A-Z]{16}\b/ },
  { code: "SECRET_GITHUB_TOKEN", score: 30, detail: "hardcoded GitHub token",
    re: /\b(ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b/ },
  { code: "SECRET_GOOGLE_KEY", score: 25, detail: "hardcoded Google API key",
    re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { code: "SECRET_PRIVATE_KEY", score: 35, detail: "private key bundled in the extension",
    re: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/ },
  { code: "SECRET_GENERIC", score: 15, detail: "looks like a hardcoded api key/secret/token",
    re: /\b(api[_-]?key|secret|passwd|password|auth[_-]?token)\b\s*[:=]\s*["'][A-Za-z0-9\-_]{16,}["']/i },
];

function checkHardcodedSecrets(files) {
  const out = [];
  const seen = new Set(); // one finding per pattern, don't spam
  for (const f of files) {
    for (const p of SECRET_PATTERNS) {
      if (seen.has(p.code)) continue;
      let hit = false;
      try { hit = p.re.test(f.content || ""); } catch { hit = false; }
      if (hit) {
        seen.add(p.code);
        out.push({ code: p.code, score: p.score, detail: `${p.detail} (first seen in ${f.name})` });
      }
    }
  }
  return out;
}

function checkWebAccessibleResources(manifest) {
  const out = [];
  const war = manifest.web_accessible_resources;
  if (!war) return out;
  if (manifest.manifest_version === 3 && Array.isArray(war)) {
    for (const entry of war) {
      const matches = (entry && entry.matches) || [];
      const resources = (entry && entry.resources) || [];
      if (matches.includes("<all_urls>") && resources.length) {
        out.push({
          code: "WAR_ALL_URLS",
          score: 15,
          detail: `${resources.length} resource(s) exposed to every site — fingerprintable, sometimes exploitable`,
        });
      }
    }
  } else if (Array.isArray(war) && war.length > 10) {
    out.push({ code: "WAR_MANY", score: 10, detail: `${war.length} web-accessible resources — large exposed surface` });
  }
  return out;
}

module.exports = {
  checkPermissions,
  checkHostPermissions,
  checkContentScripts,
  checkCodeFiles,
  checkManifestMeta,
  checkPermissionCombos,
  checkHardcodedSecrets,
  checkWebAccessibleResources,
  bandFor,
};
