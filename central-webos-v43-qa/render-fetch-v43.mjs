import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';

const EXPECTED_SHA = '8e0e3c9a2be6f9c87f54e0c70bb05d22eb6f81e3cbc0c11926753b7bf9b0d755';
const source = process.env.V43_ZIP_URL;
if (!source) throw new Error('V43_ZIP_URL is required');

const response = await fetch(source);
if (!response.ok) throw new Error(`Artifact fetch failed: ${response.status}`);
const zip = Buffer.from(await response.arrayBuffer());
const actualSha = createHash('sha256').update(zip).digest('hex');
if (actualSha !== EXPECTED_SHA) throw new Error(`Artifact SHA-256 mismatch: ${actualSha}`);

const root = resolve('v43-site');
await rm(root, { recursive: true, force: true });
await mkdir(root, { recursive: true });
let offset = 0;
let fileCount = 0;
while (offset + 30 <= zip.length && zip.readUInt32LE(offset) === 0x04034b50) {
  const flags = zip.readUInt16LE(offset + 6);
  const method = zip.readUInt16LE(offset + 8);
  const compressedSize = zip.readUInt32LE(offset + 18);
  const uncompressedSize = zip.readUInt32LE(offset + 22);
  const nameLength = zip.readUInt16LE(offset + 26);
  const extraLength = zip.readUInt16LE(offset + 28);
  if (flags !== 0) throw new Error(`Unsupported ZIP flags: ${flags}`);
  const name = zip.subarray(offset + 30, offset + 30 + nameLength).toString('utf8');
  const dataStart = offset + 30 + nameLength + extraLength;
  const dataEnd = dataStart + compressedSize;
  const target = resolve(root, name);
  if (!(target === root || target.startsWith(root + '/'))) throw new Error(`Unsafe ZIP path: ${name}`);
  if (name.endsWith('/')) {
    await mkdir(target, { recursive: true });
  } else {
    await mkdir(dirname(target), { recursive: true });
    const sourceData = zip.subarray(dataStart, dataEnd);
    const data = method === 0 ? sourceData : method === 8 ? inflateRawSync(sourceData) : null;
    if (!data) throw new Error(`Unsupported ZIP method ${method}: ${name}`);
    if (data.length !== uncompressedSize) throw new Error(`Uncompressed size mismatch: ${name}`);
    await writeFile(target, data);
    fileCount += 1;
  }
  offset = dataEnd;
}
if (fileCount < 40) throw new Error(`Artifact extraction incomplete: ${fileCount} files`);
console.log(JSON.stringify({ artifact: 'Central WebOS V4.3', sha256: actualSha, files: fileCount, status: 'verified-and-extracted' }));
