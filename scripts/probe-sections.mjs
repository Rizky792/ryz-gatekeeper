// Parse the gatekeeper wasm's Data section (id 11) and dump every segment:
// file offset, memory offset, size. The input-signal hash table lives in
// one of these segments — the segment containing the known hash entries
// (amount @ file 717377 etc.) is the table. Then dump that segment as
// u32 records to recover ALL (hashLSB, hashMSB, offset, size) entries.
import fs from "node:fs";

const buf = fs.readFileSync("./circuits/gatekeeper.wasm");
console.log("wasm size:", buf.length);

// LEB128 unsigned reader
function readU32LEB(pos) {
  let result = 0;
  let shift = 0;
  let i = pos;
  while (true) {
    const b = buf[i++];
    result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return [result, i];
}

let pos = 8; // skip magic + version
const sections = [];
while (pos < buf.length) {
  const id = buf[pos++];
  const [size, next] = readU32LEB(pos);
  pos = next;
  sections.push({ id, offset: pos, size });
  pos += size;
}
console.log("sections:", sections.map((s) => `id=${s.id} off=${s.offset} size=${s.size}`).join(" | "));

const dataSec = sections.find((s) => s.id === 11);
if (!dataSec) {
  console.log("no data section");
  process.exit(0);
}
let p = dataSec.offset;
const [count, p2] = readU32LEB(p);
p = p2;
console.log("data segments:", count);
const KNOWN_FILE_OFF = 717377;
for (let s = 0; s < count; s++) {
  const [flags, p3] = readU32LEB(p);
  p = p3;
  let memOff = null;
  if (flags === 0) {
    // init expr: opcode 0x41 (i32.const), LEB value, 0x0b (end)
    const op = buf[p++];
    const [val, p4] = readU32LEB(p);
    p = p4;
    const end = buf[p++];
    memOff = val;
  } else if (flags === 1) {
    // passive segment: no init expr
    memOff = null;
  } else if (flags === 2) {
    const [memidx, p4] = readU32LEB(p);
    p = p4;
    const op = buf[p++];
    const [val, p5] = readU32LEB(p);
    p = p5;
    const end = buf[p++];
    memOff = val;
  } else {
    console.log(`segment ${s}: unsupported flags=${flags}`);
    break;
  }
  const [segSize, p6] = readU32LEB(p);
  p = p6;
  const segFileOff = p;
  const contains = KNOWN_FILE_OFF >= segFileOff && KNOWN_FILE_OFF < segFileOff + segSize;
  console.log(`segment ${s}: flags=${flags} memOff=${memOff} fileOff=${segFileOff} size=${segSize}${contains ? "  <<< CONTAINS amount entry" : ""}`);
  p += segSize;
}
console.log("done sections");
