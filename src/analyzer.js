const fs = require("fs");
const os = require("os");
const path = require("path");
const AdmZip = require("adm-zip");
const checks = require("./checks");

const MAX_FILE_BYTES = 2 * 1024 * 1024; // don't regex a 50mb bundle, pointless

// --- loading ---------------------------------------------------------------

function readManifest(dir) {
  const p = path.join(dir, "manifest.json");
  if (!fs.existsSync(p)) throw new Error("no manifest.json found — not an extension?");
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function collectCodeFiles(dir) {
  // walk it, grab anything that could plausibly contain code
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (!/\.(js|html|htm|wasm)$/i.test(e.name)) continue;
      const stat = fs.statSync(full);
      if (stat.size > MAX_FILE_BYTES) continue; // skip the giant bundles
      out.push({
        name: path.relative(dir, full),
        content: fs.readFileSync(full, "utf8").replace(/\0/g, ""),
      });
    }
  };
  walk(dir);
  return out;
}

function stripCrxHeader(buf) {
  // crx3: Cr24 | version(3) | header_size | header | zip...
  // crx2: Cr24 | version(2) | pubkey_len | sig_len | pubkey | sig | zip...
  if (buf.subarray(0, 4).toString() !== "Cr24") throw new Error("not a crx file");
  const version = buf.readUInt32LE(4);
  let zipOffset;
  if (version === 3) {
    zipOffset = 12 + buf.readUInt32LE(8);
  } else if (version === 2) {
    zipOffset = 16 + buf.readUInt32LE(8) + buf.readUInt32LE(12);
  } else {
    throw new Error(`unsupported crx version: ${version}`);
  }
  return buf.subarray(zipOffset);
}

function extractToTemp(zipBuffer) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "crxray-"));
  new AdmZip(zipBuffer).extractAllTo(tmp, true);
  return tmp;
}

function loadExtension(input) {
  // figures out what you handed it — dir, zip, or crx — and normalizes to a dir
  const tempDirs = [];
  const cleanup = () => tempDirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true }));

  let dir;
  if (fs.statSync(input).isDirectory()) {
    dir = input;
  } else {
    const buf = fs.readFileSync(input);
    // sniff it: crx magic means skip the header, otherwise assume it's already a zip
    const zipBuf = buf.subarray(0, 4).toString() === "Cr24" ? stripCrxHeader(buf) : buf;
    dir = extractToTemp(zipBuf);
    tempDirs.push(dir);
  }

  return { dir, manifest: readManifest(dir), files: collectCodeFiles(dir), cleanup };
}

// --- analysis ---------------------------------------------------------------

function splitPermissions(manifest) {
  // mv2 mixes urls into permissions[], mv3 splits them out. normalize both.
  const named = [];
  const hosts = [...(manifest.host_permissions || [])];
  for (const p of manifest.permissions || []) {
    if (typeof p === "string" && (p === "<all_urls>" || p.includes("://"))) {
      hosts.push(p);
    } else {
      named.push(p);
    }
  }
  return { named, hosts };
}

function analyze(input) {
  const { manifest, files, cleanup } = loadExtension(input);
  try {
    const { named, hosts } = splitPermissions(manifest);

    const findings = [
      ...checks.checkManifestMeta(manifest),
      ...checks.checkPermissions(named),
      ...checks.checkHostPermissions(hosts),
      ...checks.checkContentScripts(manifest.content_scripts),
      ...checks.checkCodeFiles(files),
    ];

    findings.sort((a, b) => b.score - a.score);
    const score = Math.min(100, findings.reduce((s, f) => s + f.score, 0));

    return {
      name: manifest.name || "(unnamed)",
      version: manifest.version || "?",
      manifestVersion: manifest.manifest_version || "?",
      filesScanned: files.length,
      score,
      band: checks.bandFor(score),
      findings,
    };
  } finally {
    cleanup();
  }
}

module.exports = { analyze, loadExtension };
