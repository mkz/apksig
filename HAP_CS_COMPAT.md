# HAP CodeSign Compatibility

This document describes the changes made to `apksig` to produce APK packages whose
internal layout and page-type metadata are compatible with the OpenHarmony HAP CodeSign
scheme (`hapsigner`).

## Motivation

HAP (Harmony Ability Package) files are ZIP archives signed with a code-integrity scheme
that combines PKCS#7 and an fs-verity Merkle tree. A key part of the signing data is a
page-type **bitmap** stored in a special ZIP entry (`.pages.info`). The bitmap annotates
each 4 KiB page of the package's "runnable region" (native libraries + bytecode) with
two type bits:

| Bit (within 4-bit unit) | Meaning |
|---|---|
| 0 | Page belongs to an ELF executable (`PF_X`) segment |
| 1 | Page belongs to bytecode (DEX / ABC) |
| 2–3 | Reserved (zero) |

HAP also mandates a specific entry order so the runnable region is contiguous and can be
efficiently covered by the signing hash:

```
[uncompressed native libs (.so, .an)]
[uncompressed bytecode (.abc)]
[.pages.info  — 4 KiB-aligned, stored]
[resource / other entries]
```

Porting this layout to APK enables:
- Use of the same page-type metadata by the Android runtime or security tooling.
- A drop-in upgrade path if a unified signing scheme is adopted across platforms.

Android compatibility is preserved: APK Signature Scheme v2/v3 signs **all bytes** before
the APK Signing Block regardless of entry order, so reordering entries and inserting
`.pages.info` requires no changes to the signature verifier.

---

## APK vs. HAP mapping

| Concept | HAP | APK (this port) |
|---|---|---|
| Native libraries | `lib/*.so`, `*.an` (uncompressed) | `lib/**/*.so` (stored, `COMPRESSION_METHOD_STORED`) |
| Bytecode files | `*.abc` | `*.dex` |
| Bitmap entry | `.pages.info` | `.pages.info` (same name) |
| Bitmap placement | After last `.abc`, before other entries | After last `.dex`/`.so`, before other entries |
| Page alignment | 4 096 bytes | 4 096 bytes (native: may be 16 384 on API 35+) |
| ELF annotation | All `PF_X` program-header segments | Same |
| DEX annotation | Entire `.abc` file extent | Entire `.dex` file extent |
| Signed data boundary | `dataSize` = first non-runnable entry | v2/v3 always covers the entire pre-signing-block region |

> **Note on 16 KiB pages.** Android 15 (API 35) requires that uncompressed `.so` files be
> aligned to 16 384 bytes for devices with 16 KiB page size. The bitmap still uses 4 096-byte
> granularity (matching HAP), so each 16 KiB-aligned `.so` simply has four consecutive bitmap
> units covered. This mismatch is benign: the bitmap over-annotates at most three extra 4 KiB
> units per library.

---

## Implementation

### New file — `ApkPageInfoGenerator.java`

`com.android.apksig.ApkPageInfoGenerator` (package-private) is a self-contained port of
HAP's `PageInfoGenerator`. It requires no external dependencies beyond the existing
`apksig` utilities.

**API surface:**

```java
// Entry type classification
enum EntryType { NATIVE_LIB, DEX }

// Per-entry metadata collected during the offset-simulation pass
static class EntryInfo {
    String                  name;
    EntryType               type;
    long                    simulatedDataOffset; // absolute offset in the output APK
    long                    dataSize;            // uncompressed/stored byte count
    CentralDirectoryRecord  cdRecord;            // used to read .so bytes for ELF parsing
}

// Generates the raw bitmap bytes
static byte[] generateBitMap(
        List<EntryInfo> entries,
        long            maxEntryDataOffset,   // where .pages.info data will start
        DataSource      inputApkLfhSection)   // source for ELF program-header reads
        throws IOException;
```

**Bitmap layout** (identical to `PageInfoExtension.DEFAULT_UNIT_SIZE = 4`):

```
For page index p (0-based, each page = 4 096 bytes):
  bit  p*4 + 0 : set if any byte of the page is in an ELF PF_X segment
  bit  p*4 + 1 : set if any byte of the page is in a DEX file
  bits p*4 + 2,3 : always zero
Serialised little-endian, byte length = ceil(numPages * 4 / 8)
```

**ELF parsing** is done inline (no dependency on `hapsigner`'s `ElfFile`):
- Reads the 16-byte `e_ident`, verifies the magic (`\x7FELF`), extracts class (32/64-bit)
  and endianness.
- For 32-bit ELF: reads `e_phoff` at byte 28, `e_phentsize` at 42, `e_phnum` at 44.
- For 64-bit ELF: reads `e_phoff` at byte 32, `e_phentsize` at 54, `e_phnum` at 56.
- Iterates program headers; for each with `(p_flags & PF_X) != 0` and `p_filesz > 0`,
  maps `[p_offset, p_offset + p_filesz)` — relative to the start of the `.so` data —
  to output-APK page indices using `simulatedDataOffset`.

If the `.so` content cannot be read (malformed entry, too small to be ELF, unknown class),
ELF annotation is silently skipped for that entry; DEX annotation is always purely
offset-arithmetic and never fails.

---

### Modified file — `ApkSigner.java`

#### New private enum: `ApkEntryType`

```java
private enum ApkEntryType {
    NATIVE_LIB,          // stored lib/**/*.so
    DEX,                 // stored *.dex
    OTHER_UNCOMPRESSED,  // any other stored entry
    COMPRESSED,          // deflated (or any non-STORED) entry
    BITMAP               // .pages.info — always dropped and regenerated
}
```

The enum ordinal defines the output write order.

#### New private static method: `classifyEntry(CentralDirectoryRecord)`

```java
private static ApkEntryType classifyEntry(CentralDirectoryRecord cd) {
    String name = cd.getName();
    if (".pages.info".equals(name))                        return BITMAP;
    if (cd.getCompressionMethod() != COMPRESSION_METHOD_STORED) return COMPRESSED;
    if (name.startsWith("lib/") && name.endsWith(".so"))   return NATIVE_LIB;
    if (name.endsWith(".dex"))                             return DEX;
    return OTHER_UNCOMPRESSED;
}
```

#### New private method: `outputStoredAlignedEntry(...)`

Writes a stored, 4 KiB-aligned Local File Header + data record for `.pages.info`:

1. Computes an alignment extra field (`ID = 0xd935`, same mechanism used for native libs)
   so that the data starts on a 4 096-byte boundary.
2. Computes CRC-32 of the raw bitmap bytes.
3. Writes the LFH and data to the output sink.
4. Calls `signerEngine.outputJarEntry(".pages.info")` so the entry appears in the JAR
   (`MANIFEST.MF`) if v1 signing is active.
5. Appends a `CentralDirectoryRecord` (STORED method) to `outputCdRecords`.

Returns the number of bytes written.

#### Changes to `sign(DataSource, DataSink, DataSource)`

The original single-pass loop is replaced with a **two-pass** approach.

**Entry classification and sorting** (before writing):

```
sortedCdRecords = inputCdRecords
    .filter(cd -> classifyEntry(cd) != BITMAP)   // drop existing .pages.info
    .sortedBy(entryOrder)                        // NATIVE_LIB < DEX < OTHER_UNCOMP < COMPRESSED
                                                 // alphabetical within each group
```

**Pass 1 — offset simulation** (read-only, no I/O):

For each NATIVE_LIB and DEX entry in sorted order:
1. Read the `LocalFileRecord` from the input APK.
2. Compute the alignment extra field that `outputInputJarEntryLfhRecord` would generate at
   the simulated output position.
3. Derive `simulatedDataOffset` = simulated LFH start + header size + extra delta.
4. Accumulate `simulatedOffset` += total record size (with extra delta).

After all runnable entries, compute `maxEntryDataOffset` — the 4 KiB-aligned data start
of the future `.pages.info` record:

```
pagesInfoExtraStart  = simulatedOffset + 30 + len(".pages.info")
pagesInfoDataMinStart = pagesInfoExtraStart + 6   // ALIGNMENT_ZIP_EXTRA_DATA_FIELD_MIN_SIZE_BYTES
maxEntryDataOffset   = ceil(pagesInfoDataMinStart / 4096) * 4096
```

Call `ApkPageInfoGenerator.generateBitMap(runnableEntries, maxEntryDataOffset, inputApkLfhSection)`
to produce the bitmap bytes. If there are no runnable entries, skip bitmap generation.

**Pass 2 — write loop**:

Iterates `sortedCdRecords`. Before writing the first `OTHER_UNCOMPRESSED` or `COMPRESSED`
entry (i.e., immediately after the last DEX entry), inserts `.pages.info` via
`outputStoredAlignedEntry`. If the APK contains only runnable entries, the bitmap is
appended after the write loop instead.

All other per-entry logic (signing-engine callbacks, alignment re-writing via
`outputInputJarEntryLfhRecord`, pin-byte-range tracking) is unchanged.

**Signing engine notification for the old `.pages.info`:**
Before the write loop, any existing `.pages.info` entry in the input is reported to the
signer engine via `signerEngine.inputJarEntry(".pages.info")` so the engine's internal
state stays consistent. The regenerated entry is reported via `outputJarEntry` inside
`outputStoredAlignedEntry`.

---

### Modified file — `CentralDirectoryRecord.java`

Added `createWithStoredData(name, lastModifiedTime, lastModifiedDate, crc32, size,
localFileHeaderOffset)`, a static factory that builds a CD record with
`COMPRESSION_METHOD_STORED` (compressed size = uncompressed size). Analogous to the
existing `createWithDeflateCompressedData`.

---

## Invariants preserved

| Property | Status |
|---|---|
| v2/v3 signature validity | ✅ Unchanged — signs all bytes before the APK Signing Block; `.pages.info` is included automatically |
| v1 (JAR) signature validity | ✅ `.pages.info` appears in `MANIFEST.MF`; benign for Android verifiers |
| v4 (fs-verity) signature | ✅ Computed over the final output; entry order is irrelevant |
| `AndroidManifest.xml` still present | ✅ Classified as COMPRESSED or OTHER_UNCOMPRESSED; never dropped |
| Source stamp / pin-list entries | ✅ Handled by dedicated existing code paths after the main loop |
| APKs without native libs or DEX | ✅ No `.pages.info` is inserted (bitmap generation is skipped) |
| Idempotency (re-signing) | ✅ Any existing `.pages.info` is dropped and regenerated fresh |

---

## Output layout example

For an APK containing `lib/arm64-v8a/libfoo.so`, `classes.dex`, and `res/layout/main.xml`:

```
[offset 0]
  LFH  lib/arm64-v8a/libfoo.so   (stored, 16 KiB-aligned data start)
  DATA  <ELF content>
[offset A]
  LFH  classes.dex               (stored, 4-byte-aligned data start)
  DATA  <DEX content>
[offset B — 4 KiB-aligned]
  LFH  .pages.info               (stored, 4 KiB-aligned data start)
  DATA  <bitmap>
[offset C]
  LFH  res/layout/main.xml       (deflated)
  DATA  <compressed content>
[APK Signing Block]
[Central Directory]
[End of Central Directory]
```

The bitmap covers pages `[0, B/4096)`, annotating each 4 KiB page with the type bits
corresponding to whichever ELF exec-segment or DEX byte falls within it.
