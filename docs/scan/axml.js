// ZIP and binary AndroidManifest (AXML) parsing for the in-browser scanner. No libraries.
'use strict';

const ATTR_IDS = {
  0x01010003: 'name', 0x01010010: 'exported', 0x01010006: 'permission', 0x01010007: 'readPermission',
  0x0101000f: 'debuggable', 0x01010280: 'allowBackup', 0x010104ec: 'usesCleartextTraffic',
  0x01010527: 'networkSecurityConfig', 0x0101020c: 'minSdkVersion', 0x01010270: 'targetSdkVersion',
  0x0101021c: 'versionName',
};

async function readZipEntry(buf, wanted) {
  const v = new DataView(buf);
  let eocd = -1;
  for (let i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 65557); i--) {
    if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a valid APK (ZIP directory not found).');
  let p = v.getUint32(eocd + 16, true);
  const count = v.getUint16(eocd + 10, true), dec = new TextDecoder();
  for (let n = 0; n < count && v.getUint32(p, true) === 0x02014b50; n++) {
    const method = v.getUint16(p + 10, true), csize = v.getUint32(p + 20, true);
    const nlen = v.getUint16(p + 28, true), elen = v.getUint16(p + 30, true), clen = v.getUint16(p + 32, true);
    const local = v.getUint32(p + 42, true);
    if (dec.decode(new Uint8Array(buf, p + 46, nlen)) === wanted) {
      const start = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
      const data = new Uint8Array(buf, start, csize);
      if (method === 0) return data;
      if (method !== 8) throw new Error('Unsupported compression in APK.');
      const s = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
      return new Uint8Array(await new Response(s).arrayBuffer());
    }
    p += 46 + nlen + elen + clen;
  }
  throw new Error(wanted + ' not found in APK.');
}

function readStringPool(v, p, hsize) {
  const count = v.getUint32(p + 8, true), utf8 = (v.getUint32(p + 16, true) & 0x100) !== 0;
  const start = p + v.getUint32(p + 20, true), out = [];
  const u8 = new TextDecoder('utf-8'), u16 = new TextDecoder('utf-16le');
  for (let i = 0; i < count; i++) {
    let o = start + v.getUint32(p + hsize + i * 4, true);
    if (utf8) {
      o += (v.getUint8(o) & 0x80) ? 2 : 1;  // skip UTF-16 length
      let len = v.getUint8(o);
      if (len & 0x80) { len = ((len & 0x7f) << 8) | v.getUint8(o + 1); o += 2; } else { o += 1; }
      out.push(u8.decode(new Uint8Array(v.buffer, v.byteOffset + o, len)));
    } else {
      let len = v.getUint16(o, true);
      if (len & 0x8000) { len = ((len & 0x7fff) << 16) | v.getUint16(o + 2, true); o += 4; } else { o += 2; }
      out.push(u16.decode(new Uint8Array(v.buffer, v.byteOffset + o, len * 2)));
    }
  }
  return out;
}

function parseAxml(bytes) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let strings = [];
  const resMap = [], root = { tag: '#root', attrs: {}, children: [] }, stack = [root];
  for (let p = 8; p + 8 <= bytes.byteLength;) {
    const type = v.getUint16(p, true), hsize = v.getUint16(p + 2, true), size = v.getUint32(p + 4, true);
    if (size < 8) break;
    if (type === 0x0001) strings = readStringPool(v, p, hsize);
    else if (type === 0x0180) { for (let i = p + 8; i < p + size; i += 4) resMap.push(v.getUint32(i, true)); }
    else if (type === 0x0102) {
      const ext = p + 16;
      const node = { tag: strings[v.getUint32(ext + 4, true)] || '?', attrs: {}, children: [] };
      const aStart = v.getUint16(ext + 8, true), aSize = v.getUint16(ext + 10, true), aCount = v.getUint16(ext + 12, true);
      for (let i = 0; i < aCount; i++) {
        const a = ext + aStart + i * aSize;
        const idx = v.getUint32(a + 4, true), raw = v.getUint32(a + 8, true);
        const dtype = v.getUint8(a + 15), data = v.getUint32(a + 16, true);
        const name = ATTR_IDS[resMap[idx]] || strings[idx] || '';
        let value;
        if (raw !== 0xffffffff) value = strings[raw];
        else if (dtype === 0x12) value = data !== 0 ? 'true' : 'false';
        else if (dtype === 0x03) value = strings[data];
        else value = String(data | 0);
        if (name) node.attrs[name] = value;
      }
      stack[stack.length - 1].children.push(node);
      stack.push(node);
    } else if (type === 0x0103 && stack.length > 1) stack.pop();
    p += size;
  }
  return root;
}

function findAll(node, tag, out = []) {
  for (const c of node.children) { if (c.tag === tag) out.push(c); findAll(c, tag, out); }
  return out;
}
