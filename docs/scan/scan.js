// ProofDroid in-browser scan: manifest rules + rendering (textContent only, no innerHTML).
'use strict';

const TYPES = { activity: 'Activity', 'activity-alias': 'Activity-Alias', service: 'Service',
  receiver: 'Broadcast Receiver', provider: 'Content Provider' };
const MAX_BYTES = 300 * 1024 * 1024;
const isTrue = (v) => ['true', '-1'].includes(String(v || '').toLowerCase());

function analyze(root) {
  const manifest = findAll(root, 'manifest')[0], app = findAll(root, 'application')[0];
  if (!manifest || !app) throw new Error('Could not read AndroidManifest.xml.');
  const sdk = findAll(manifest, 'uses-sdk')[0] || { attrs: {} };
  const minSdk = parseInt(sdk.attrs.minSdkVersion || '1', 10), target = parseInt(sdk.attrs.targetSdkVersion || '1', 10);
  const a = app.attrs, out = [];
  const add = (severity, title, why) => out.push({ severity, title, why });

  if (isTrue(a.debuggable)) add('High', 'App is debuggable (android:debuggable=true)',
    'Anyone with USB/adb access can run code as the app and read its private files.');
  if (a.usesCleartextTraffic === undefined ? (target < 28 && !a.networkSecurityConfig) : isTrue(a.usesCleartextTraffic))
    add('High', 'Cleartext (plain HTTP) traffic allowed', `Network traffic may be readable on public Wi-Fi (targetSdk ${target}).`);
  if (a.allowBackup === undefined || isTrue(a.allowBackup)) add('Medium', 'App data can be backed up (allowBackup)',
    'App data can be copied off the device with adb backup.');
  if (minSdk < 24) add('Medium', `Installs on old, unpatched Android (minSdk ${minSdk})`, 'Older Android versions no longer get security fixes.');

  for (const [tag, label] of Object.entries(TYPES)) {
    for (const c of findAll(app, tag)) {
      const filters = findAll(c, 'intent-filter');
      const launcher = filters.some((f) => findAll(f, 'category').some((x) => x.attrs.name === 'android.intent.category.LAUNCHER'));
      const exported = c.attrs.exported !== undefined ? isTrue(c.attrs.exported) : (filters.length > 0 || (tag === 'provider' && target < 17));
      if (launcher || !exported || !c.attrs.name) continue;
      const perm = c.attrs.permission || c.attrs.readPermission;
      if (perm) add('Info', `${label} ${c.attrs.name} is exported (guarded by ${perm})`, 'Check the permission\'s protection level.');
      else add(tag === 'provider' ? 'High' : 'Medium', `${label} ${c.attrs.name} is exported with no permission`,
        `Any other app on the device can reach this ${label.toLowerCase()}.`);
    }
  }
  const order = { High: 0, Medium: 1, Info: 2 };
  out.sort((x, y) => order[x.severity] - order[y.severity]);
  return { pkg: manifest.attrs.package || '?', version: manifest.attrs.versionName || '', minSdk, target, findings: out };
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function render(r, fileName) {
  const box = document.getElementById('result');
  box.replaceChildren();
  box.appendChild(el('h2', `${r.pkg} ${r.version}`));
  box.appendChild(el('p', `${fileName} · minSdk ${r.minSdk} · targetSdk ${r.target} · ${r.findings.length} findings`, 'muted'));
  const table = el('table');
  const head = el('tr');
  ['Severity', 'Finding', 'Why it matters'].forEach((h) => head.appendChild(el('th', h)));
  table.appendChild(head);
  for (const f of r.findings) {
    const row = el('tr');
    row.appendChild(el('td', f.severity, 'sev-' + f.severity.toLowerCase()));
    row.appendChild(el('td', f.title));
    row.appendChild(el('td', f.why));
    table.appendChild(row);
  }
  box.appendChild(table);
  box.appendChild(el('p', 'These are static findings only (nothing was executed). To prove which ones are exploitable, '
    + 'run the full scan on GitHub Actions or locally with the CLI.', 'note'));
}

async function handle(file) {
  const status = document.getElementById('status');
  document.getElementById('result').replaceChildren();
  try {
    if (!file.name.toLowerCase().endsWith('.apk')) throw new Error('Please choose an .apk file.');
    if (file.size > MAX_BYTES) throw new Error('APK is larger than 300 MB.');
    status.textContent = 'Reading APK in your browser…';
    const buf = await file.arrayBuffer();
    if (new DataView(buf).getUint32(0, true) !== 0x04034b50) throw new Error('Not an APK (missing ZIP header).');
    render(analyze(parseAxml(await readZipEntry(buf, 'AndroidManifest.xml'))), file.name);
    status.textContent = 'Done. Your APK was not uploaded anywhere.';
  } catch (e) {
    status.textContent = 'Error: ' + (e && e.message ? e.message : 'could not parse this APK.');
  }
}

document.getElementById('apk').addEventListener('change', (e) => e.target.files[0] && handle(e.target.files[0]));
const drop = document.getElementById('drop');
drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) handle(e.dataTransfer.files[0]); });
