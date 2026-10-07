#!/usr/bin/env node
// crxray — point it at a chrome extension, get a risk readout.

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const { analyze } = require("./analyzer");
const { printReport } = require("./reporter");

const BANDS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function usage() {
  console.log(`
crxray <path | extension-id> [options]

  path            unpacked extension dir, .zip, or .crx file
  extension-id    32-char web store id, downloads the crx for you

options:
  --json               machine-readable output
  --fail-on <band>     exit 1 if risk is band or worse (for CI)
  --out <file>         write the report (json) to a file
  -h, --help           this
`.trim());
}

// web store download — google's update api hands back a redirect to the crx
function downloadCrx(id) {
  const url = `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0&acceptformat=crx2,crx3&x=id%3D${id}%26installsource%3Dondemand%26uc`;
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        https.get(res.headers.location, (r2) => collectBody(r2, resolve, reject)).on("error", reject);
      } else {
        collectBody(res, resolve, reject);
      }
    }).on("error", reject);
  });
}

function collectBody(res, resolve, reject) {
  if (res.statusCode !== 200) {
    reject(new Error(`download failed, http ${res.statusCode}`));
    res.resume();
    return;
  }
  const chunks = [];
  res.on("data", (c) => chunks.push(c));
  res.on("end", () => resolve(Buffer.concat(chunks)));
}

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args.includes("-h") || args.includes("--help")) {
    usage();
    process.exit(args.length ? 0 : 1);
  }

  let input = null, json = false, failOn = null, out = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--fail-on") failOn = (args[++i] || "").toUpperCase();
    else if (a === "--out") out = args[++i];
    else if (!input) input = a;
    else { console.error(`unexpected arg: ${a}`); process.exit(1); }
  }
  if (failOn && !BANDS.includes(failOn)) {
    console.error(`--fail-on must be one of ${BANDS.join("|")}`);
    process.exit(1);
  }

  // 32 lowercase letters = probably a web store id, go fetch it
  if (/^[a-z]{32}$/.test(input)) {
    console.error(`fetching ${input} from the web store...`);
    const buf = await downloadCrx(input);
    const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "crxray-")), "ext.crx");
    fs.writeFileSync(tmp, buf);
    input = tmp;
  } else if (!fs.existsSync(input)) {
    console.error(`not found: ${input}`);
    process.exit(1);
  }

  let result;
  try {
    result = analyze(input);
  } catch (e) {
    console.error(`analysis failed: ${e.message}`);
    process.exit(1);
  }

  if (out) {
    fs.writeFileSync(out, JSON.stringify(result, null, 2));
    console.error(`wrote ${out}`);
  }
  printReport(result, { json });

  if (failOn && BANDS.indexOf(result.band) >= BANDS.indexOf(failOn)) process.exit(1);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
