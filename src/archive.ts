/**
 * A minimal, dependency-free ZIP writer.
 *
 * WHY THIS IS HAND-WRITTEN RATHER THAN `fflate`
 * ---------------------------------------------
 * keel-migrate has zero runtime dependencies, and that is not an aesthetic
 * preference — it is the security argument the README makes. This tool is handed
 * live, read-only API credentials for a customer's compliance platform and told
 * to run on their laptop. "Nothing but Node's standard library is in the loop"
 * is a claim an auditor can check in one command (`npm ls --omit=dev`), and it
 * survives without us: no transitive graph to re-audit, no supply-chain
 * surface, nothing that can be compromised upstream between two of our releases.
 * This repo has already been burned by a malicious package release elsewhere in
 * the org, so that property is worth real code.
 *
 * The cost of keeping it is bounded and known: ZIP's store/deflate profile is
 * ~120 lines of fully-specified format (PKWARE APPNOTE 4.3.6 — local file
 * header, then the central directory, then the end-of-central-directory
 * record), and Node's `zlib.deflateRawSync` supplies the only hard part, the
 * compressor. The remaining work is byte layout and a CRC-32, both of which are
 * table-driven and testable. `fflate` would save those lines and cost the
 * headline property; that trade is not worth it here. (In keelgrc-v1, where
 * fflate is *already* a dependency and the runtime is a Cloudflare Worker with
 * no `node:zlib`, the answer is the opposite and we use fflate — see
 * apps/app/src/lib/migrate/archive.ts.)
 *
 * Scope limits, deliberately: no ZIP64, no encryption, no directory entries, no
 * data descriptors. Everything is written with sizes known up front, so the
 * output is the simplest form every unzip implementation reads. Inputs beyond
 * the classic limits (65,535 entries or 4 GiB) are rejected loudly rather than
 * silently truncated — a corrupt archive that only fails at import time is the
 * one outcome worse than no archive at all.
 */
import { deflateRawSync } from 'node:zlib';

/** Entries beyond these limits need ZIP64, which this writer does not emit. */
const MAX_ENTRIES = 0xffff;
const MAX_SIZE = 0xffffffff;

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c;
  }
  return t;
})();

/** CRC-32 (IEEE 802.3), the checksum ZIP stores for every entry. */
export function crc32(buf: Buffer): number {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

/** MS-DOS date/time pair (APPNOTE 4.4.6), the only timestamp a base ZIP carries. */
function dosDateTime(at: Date): { time: number; date: number } {
  // DOS epoch is 1980 and seconds have 2-second resolution. Values before 1980
  // are unrepresentable; clamp rather than emit a negative year field.
  const year = Math.max(1980, at.getFullYear());
  return {
    time: (at.getHours() << 11) | (at.getMinutes() << 5) | (at.getSeconds() >> 1),
    date: ((year - 1980) << 9) | ((at.getMonth() + 1) << 5) | at.getDate(),
  };
}

interface PendingEntry {
  nameBytes: Buffer;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  offset: number;
  local: Buffer;
  data: Buffer;
}

/**
 * Builds a ZIP incrementally so the caller can hand over one shard at a time and
 * drop its JSON string immediately. Only the *compressed* bytes are retained,
 * which for a bundle (mostly base64 of already-compressed documents) is close to
 * the size of the underlying files rather than of the JSON.
 */
export class ZipBuilder {
  private entries: PendingEntry[] = [];
  private offset = 0;

  constructor(private readonly modifiedAt: Date = new Date()) {}

  /** Add one deflated entry. `name` is a forward-slash path, `data` its bytes. */
  add(name: string, data: Buffer): void {
    if (this.entries.length >= MAX_ENTRIES) {
      throw new Error(`Cannot write more than ${MAX_ENTRIES} files into one archive.`);
    }
    const nameBytes = Buffer.from(name, 'utf8');
    const compressed = deflateRawSync(data, { level: 9 });
    if (data.length > MAX_SIZE || compressed.length > MAX_SIZE) {
      throw new Error(`"${name}" is too large for a non-ZIP64 archive (4 GiB limit).`);
    }
    const { time, date } = dosDateTime(this.modifiedAt);

    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4); // version needed to extract (2.0 = deflate)
    local.writeUInt16LE(0x0800, 6); // general purpose flags: bit 11 = UTF-8 names
    local.writeUInt16LE(8, 8); // compression method: deflate
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28); // extra field length
    nameBytes.copy(local, 30);

    this.entries.push({
      nameBytes,
      crc: crc32(data),
      compressedSize: compressed.length,
      uncompressedSize: data.length,
      offset: this.offset,
      local,
      data: compressed,
    });
    this.offset += local.length + compressed.length;
  }

  /** Finish the archive: central directory + end-of-central-directory record. */
  finish(): Buffer {
    const parts: Buffer[] = [];
    for (const e of this.entries) {
      parts.push(e.local, e.data);
    }

    const centralStart = this.offset;
    const { time, date } = dosDateTime(this.modifiedAt);
    let centralSize = 0;
    for (const e of this.entries) {
      const h = Buffer.alloc(46 + e.nameBytes.length);
      h.writeUInt32LE(0x02014b50, 0); // central file header signature
      h.writeUInt16LE(20, 4); // version made by
      h.writeUInt16LE(20, 6); // version needed to extract
      h.writeUInt16LE(0x0800, 8); // flags (UTF-8 names)
      h.writeUInt16LE(8, 10); // deflate
      h.writeUInt16LE(time, 12);
      h.writeUInt16LE(date, 14);
      h.writeUInt32LE(e.crc, 16);
      h.writeUInt32LE(e.compressedSize, 20);
      h.writeUInt32LE(e.uncompressedSize, 24);
      h.writeUInt16LE(e.nameBytes.length, 28);
      h.writeUInt16LE(0, 30); // extra field length
      h.writeUInt16LE(0, 32); // file comment length
      h.writeUInt16LE(0, 34); // disk number start
      h.writeUInt16LE(0, 36); // internal file attributes
      h.writeUInt32LE(0o644 << 16, 38); // external attributes: regular file, rw-r--r--
      h.writeUInt32LE(e.offset, 42); // relative offset of local header
      e.nameBytes.copy(h, 46);
      parts.push(h);
      centralSize += h.length;
    }

    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0); // end of central directory signature
    eocd.writeUInt16LE(0, 4); // this disk
    eocd.writeUInt16LE(0, 6); // disk with the central directory
    eocd.writeUInt16LE(this.entries.length, 8);
    eocd.writeUInt16LE(this.entries.length, 10);
    eocd.writeUInt32LE(centralSize, 12);
    eocd.writeUInt32LE(centralStart, 16);
    eocd.writeUInt16LE(0, 20); // comment length
    parts.push(eocd);

    const total = centralStart + centralSize + eocd.length;
    if (total > MAX_SIZE) {
      throw new Error(
        'The archive exceeded 4 GiB, which needs ZIP64. Re-run with --no-archive and ' +
          'import the individual bundle files.',
      );
    }
    return Buffer.concat(parts);
  }
}

/** Convenience wrapper: build a whole archive from a list of entries. */
export function zipSync(entries: { name: string; data: Buffer }[], modifiedAt?: Date): Buffer {
  const zip = new ZipBuilder(modifiedAt);
  for (const e of entries) zip.add(e.name, e.data);
  return zip.finish();
}
