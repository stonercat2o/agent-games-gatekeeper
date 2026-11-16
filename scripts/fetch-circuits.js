// Fetches the official gatekeeper circuit artifacts into circuits/ when
// they are missing. Hosted deploys run this at boot: the binaries are
// deliberately not committed to git (see .gitignore), so a fresh checkout
// downloads them from the tournament site instead.
const fs = require('fs');
const https = require('https');
const path = require('path');

const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');
const ARTIFACTS = [
  ['gatekeeper.wasm', 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm'],
  ['gatekeeper_final.zkey', 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey'],
];

function downloadTo(url, destination, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (redirectsLeft === 0) return reject(new Error(`too many redirects for ${url}`));
          return resolve(downloadTo(res.headers.location, destination, redirectsLeft - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
        }
        const tmpPath = destination + '.part';
        const file = fs.createWriteStream(tmpPath);
        res.pipe(file);
        file.on('finish', () =>
          file.close(() => {
            fs.renameSync(tmpPath, destination);
            resolve();
          })
        );
        file.on('error', reject);
      })
      .on('error', reject);
  });
}

async function ensureCircuits() {
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });
  for (const [name, url] of ARTIFACTS) {
    const dest = path.join(CIRCUITS_DIR, name);
    if (fs.existsSync(dest) && fs.statSync(dest).size > 0) continue;
    console.log(`[circuits] downloading ${name}`);
    await downloadTo(url, dest);
  }
}

if (require.main === module) {
  ensureCircuits()
    .then(() => console.log('[circuits] artifacts ready'))
    .catch((err) => {
      console.error('[circuits] failed:', err.message);
      process.exit(1);
    });
}

module.exports = { ensureCircuits, CIRCUITS_DIR };
