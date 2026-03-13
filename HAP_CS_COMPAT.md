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

---

## Phase 2: Code Sign Block + fs-verity Enablement

Phase 1 produced the entry ordering and `.pages.info` bitmap. Phase 2 adds the
**code sign block** — a binary structure embedded in the APK Signing Block that carries
an fs-verity root hash, a PKCS#7 signature, and pointers to the page-type bitmap. A
companion **apkverify** tool reads this block and calls `ioctl(fd, FS_IOC_ENABLE_CODE_SIGN)`
to enable kernel-level on-access verification.

### Why a separate signing block?

V2/V3 signing blocks cannot be reused because:

1. **Different digest model.** V2/V3 signs 1 MB content-chunk digests. The kernel expects
   an fs-verity Merkle-tree root hash (4 KiB SHA-256 tree, bottom-up).
2. **Different consumer.** V2/V3 is consumed by PackageManager at install time. The code
   sign block is consumed by the kernel at runtime.
3. **Page-level metadata.** The kernel needs `pgtypeinfo_off`/`pgtypeinfo_size` for the
   bitmap; V2/V3 has no such concept.
4. **HAP compatibility.** The binary layout matches `security_code_signature`'s
   `code_sign_utils.cpp`, so the same kernel code path handles both HAP and APK files.
5. **Non-interference.** The block uses its own ID (`0x4F484353` — "OHCS") in the APK
   Signing Block. Standard Android verifiers skip unknown IDs, so V2/V3 remains intact.

### Why no inlined Merkle tree?

HAP optionally stores the Merkle tree inline (`FLAG_MERKLE_TREE_INLINED`), but this is
an optimization, not a requirement. The kernel computes the tree itself during
`FS_IOC_ENABLE_CODE_SIGN` (identical to `FS_IOC_ENABLE_VERITY`). We store only the
**root hash** (64 bytes, for verification) and the **PKCS#7 signature** (proves
authenticity). This keeps the block small (a few KB) instead of megabytes.

`tree_offset` is set to 0 and `flags` does NOT include `FLAG_MERKLE_TREE_INLINED` (0x1).

---

### Code Sign Block binary layout

The block is stored as an ID-value pair in the APK Signing Block:

```
APK Signing Block pair:
  ID:    0x4F484353  ("OHCS")
  Value: <code sign block bytes>
```

The value has this structure:

```
CodeSignBlockHeader          32 bytes
SegmentHeader[0]             12 bytes    FSVERITY_INFO (type=1)
SegmentHeader[1]             12 bytes    HAP_META      (type=2)
SegmentHeader[2]             12 bytes    NATIVE_LIB_INFO (type=3)
FsVerityInfoSegment          64 bytes
HapInfoSegment               variable
NativeLibInfoSegment         12 bytes    (stub)
```

#### CodeSignBlockHeader (32 bytes)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 8 | magic | `0x5389FCCDE046C8C6` (LE) |
| 8 | 4 | version | 1 |
| 12 | 4 | blockSize | total size of the entire code sign block |
| 16 | 4 | segmentNum | 3 |
| 20 | 4 | flags | 0x0 (no Merkle tree inlined) |
| 24 | 8 | reserved | 0 |

#### SegmentHeader (12 bytes each)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | type (1=FSVERITY_INFO, 2=HAP_META, 3=NATIVE_LIB_INFO) |
| 4 | 4 | offset (from start of code sign block) |
| 8 | 4 | size |

#### FsVerityInfoSegment (64 bytes)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | magic | `0x31AB1E38` |
| 4 | 1 | version | 1 |
| 5 | 1 | hashAlgorithm | 1 (SHA-256) |
| 6 | 1 | logBlockSize | 12 (= 4096 bytes) |
| 7 | 57 | reserved | zeros |

#### HapInfoSegment (variable)

```
u32  magic          0xCC66C1B5
---- SignInfo ----
u32  saltSize       0
u32  sigSize        length of PKCS#7 signature
u32  flags          0x0 (no Merkle tree inlined)
u64  dataSize       LFH section size (bytes covered by Merkle tree)
u8[32] salt         zeros
u32  extensionNum   1 or 2
u32  extensionOffset  offset from SignInfo start to first extension
u8[sigSize] signature  PKCS#7 DER over FsVerityDescriptor
u8[0-3] padding     alignment to 4 bytes
---- MerkleTreeExtension (88 bytes) ----
u32  type           1
u32  size           80
u64  treeSize       0 (not inlined)
u64  treeOffset     0 (kernel computes)
u8[64] rootHash     SHA-256 root hash, zero-padded to 64 bytes
---- PageInfoExtension (32 bytes, present if .pages.info exists) ----
u32  type           2
u32  size           24
u64  mapOffset      absolute file offset of .pages.info data
u64  mapSize        bitmap byte count
u8   unitSize       4 (bits per page)
u8[3] reserved      zeros
u32  signSize       0 (page-info signature not yet implemented)
```

#### NativeLibInfoSegment (12-byte stub)

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | magic | `0x0ED2E720` |
| 4 | 4 | length | 12 |
| 8 | 4 | sectionNum | 0 |

---

### FsVerityDescriptor (256 bytes, signed data)

The PKCS#7 signature covers a 256-byte FsVerityDescriptor (little-endian), identical
in layout to HAP's `FsVerityDescriptor.java`. The **digest form** (used as the signed
payload) has `signSize = 0`:

| Offset | Size | Field | Value (digest form) |
|--------|------|-------|---------------------|
| 0 | 1 | version | 1 |
| 1 | 1 | hashAlgorithm | 1 (SHA-256) |
| 2 | 1 | log2BlockSize | 12 |
| 3 | 1 | saltSize | 0 |
| 4 | 4 | signSize | **0** |
| 8 | 8 | dataSize | LFH section size |
| 16 | 64 | rootHash | SHA-256 root hash, zero-padded |
| 80 | 32 | salt | zeros |
| 112 | 4 | flags | `(unitSize << 1) \| 0` = 8 |
| 116 | 4 | mapSize | bitmap byte count |
| 120 | 8 | merkleTreeOffset | 0 |
| 128 | 8 | mapOffset | absolute file offset of bitmap data |
| 136 | 119 | reserved | zeros |
| 255 | 1 | csVersion | 2 |

---

### Signing-side implementation

#### New files

| File | Purpose |
|------|---------|
| `internal/codesign/CodeSignConstants.java` | All magic numbers, segment types, sizes, flags |
| `internal/codesign/FsVerityDescriptor.java` | 256-byte descriptor builder; `getDigestBytes()` returns the signing payload |
| `internal/codesign/CodeSignBlock.java` | `build(rootHash, signature, dataSize, mapOffset, mapSize)` assembles the complete binary block |

#### Modified files

**`ApkSigningBlockUtils.java`** — added constant:
```java
public static final int APK_CODE_SIGN_BLOCK_ID = 0x4F484353;
```

**`DefaultApkSignerEngine.java`** — new opt-in flag and plumbing:
- `boolean mCodeSignEnabled` field (default `false`)
- `Builder.setCodeSignEnabled(boolean)` — enables code signing
- `isCodeSignEnabled()` — queried by `ApkSigner`
- `setCodeSignBlock(byte[])` — receives pre-built block bytes from `ApkSigner`
- `getFirstSignerConfig()` — exposes the signing key for PKCS#7 generation
- In `outputZipSectionsInternal()`, if code signing is enabled and a block is set,
  adds `Pair.of(mCodeSignBlock, APK_CODE_SIGN_BLOCK_ID)` to the signing scheme
  blocks list before `generateApkSigningBlock()` is called.

**`ApkSigner.java`** — new opt-in flag and code sign computation:
- `boolean mCodeSignEnabled` field, `Builder.setCodeSignEnabled(boolean)`
- Wired into `DefaultApkSignerEngine.Builder.setCodeSignEnabled()`
- **Step 10.5** (between EOCD construction and `outputZipSections2()`): calls
  `buildAndSetCodeSignBlock()` if code signing is enabled.

#### `buildAndSetCodeSignBlock()` flow

```
1. Slice outputApkIn[0..outputCentralDirStartOffset] as lfhSection
2. VerityTreeBuilder(salt=null).generateVerityTreeRootHash(lfhSection) → rootHash32
3. Zero-pad rootHash32 to 64 bytes
4. Scan outputCdRecords for ".pages.info" → mapOffset, mapSize
   (reads LocalFileRecord to get exact data offset within the LFH)
5. Build FsVerityDescriptor(hashAlg=SHA256, log2Block=12, saltSize=0,
     dataSize=lfhSectionSize, rootHash, salt=zeros, flags=0,
     treeOffset=0, mapOffset, mapSize, unitSize=4)
6. descriptorDigestBytes = descriptor.getDigestBytes()  (256 bytes, signSize=0)
7. Determine JCA signature algorithm from first signer's public key type:
     RSA → "SHA256withRSA"
     EC  → "SHA256withECDSA"
     DSA → "SHA256withDSA"
8. SignerEngineFactory.getImplementation(keyConfig, jcaAlg, null)
     .sign(descriptorDigestBytes) → raw signatureBytes
9. ApkSigningBlockUtils.generatePkcs7DerEncodedMessage(
     signatureBytes, null /*detached*/, certs, digestAlgId, sigAlgId)
     → pkcs7Signature (DER-encoded PKCS#7 ContentInfo)
10. CodeSignBlock.build(rootHash, pkcs7Signature, lfhSectionSize,
      mapOffset, mapSize) → codeSignBlock bytes
11. engine.setCodeSignBlock(codeSignBlock)
```

The PKCS#7 structure is a detached signature (no embedded content) using the existing
`generatePkcs7DerEncodedMessage` utility, with the same key pair used for V2/V3 signing.

---

### APK Verify tool (`apkverify`)

A Java CLI tool with JNI for the kernel ioctl. Located in `src/apkverify/`.

#### Java files

| File | Purpose |
|------|---------|
| `ApkVerifyTool.java` | CLI entry point |
| `CodeSignBlockParser.java` | Parses the binary code sign block into fields |
| `CodeSignEnableArg.java` | POJO mirroring `struct code_sign_enable_arg` |
| `FsVerityEnabler.java` | JNI wrapper for the ioctl |

#### Native files

| File | Purpose |
|------|---------|
| `native/code_sign_enable_arg.h` | Defines the OpenHarmony kernel struct and ioctl number |
| `native/fsverity_enable_jni.c` | JNI implementation |

#### `ApkVerifyTool` flow

```
1. Open APK as RandomAccessFile → DataSource
2. ApkUtils.findZipSections(apk)
3. ApkUtils.findApkSigningBlock(apk, zipSections)
4. ApkSigningBlockUtilsLite.findApkSignatureSchemeBlock(block, 0x4F484353)
     → code sign block ByteBuffer
5. CodeSignBlockParser.parse(blockBytes) → extracts:
     - FsVerityInfo: hashAlgorithm, logBlockSize
     - SignInfo: saltSize, sigSize, flags, dataSize, salt, signature
     - MerkleTreeExtension: merkleTreeSize, merkleTreeOffset, rootHash
     - PageInfoExtension (optional): mapOffset, mapSize, unitSize
6. Print parsed fields
7. If not --dry-run, build CodeSignEnableArg and call
     FsVerityEnabler.enableCodeSign(path, ...)
```

#### `CodeSignBlockParser` internals

The parser reads the block sequentially:

1. Validates the 8-byte header magic (`0x5389FCCDE046C8C6`).
2. Reads `version`, `blockSize`, `segmentNum`, `flags`, and skips `reserved`.
3. Reads `segmentNum` segment headers (type, offset, size).
4. For each segment, seeks to its offset and dispatches:
   - **FSVERITY_INFO (1):** reads magic, version, hashAlgorithm, logBlockSize.
   - **HAP_META (2):** reads HapInfoSegment magic, then SignInfo fields (saltSize,
     sigSize, flags, dataSize, salt, extensionNum, extensionOffset, signature bytes),
     skips alignment padding, then reads extensions (MerkleTreeExtension,
     PageInfoExtension).
   - **NATIVE_LIB_INFO (3):** skipped (stub).

---

### Kernel ioctl: `FS_IOC_ENABLE_CODE_SIGN`

The ioctl is defined as:

```c
#define FS_IOC_ENABLE_CODE_SIGN _IOW('f', 136, struct code_sign_enable_arg)
```

#### `struct code_sign_enable_arg`

```c
struct code_sign_enable_arg {
    __u32 version;           // 1
    __u32 cs_version;        // 2 (page-info support)
    __u32 hash_algorithm;    // 1 (SHA-256)
    __u32 block_size;        // 4096
    __u32 salt_size;         // 0 (or length of salt)
    __u32 sig_size;          // PKCS#7 signature byte count
    __u32 pgtypeinfo_size;   // bitmap byte count (0 if no bitmap)
    __u64 salt_ptr;          // userspace pointer to salt bytes
    __u64 sig_ptr;           // userspace pointer to PKCS#7 signature
    __u64 data_size;         // LFH section size (Merkle tree input)
    __u64 tree_offset;       // 0 (kernel computes tree)
    __u64 root_hash_ptr;     // userspace pointer to 64-byte root hash
    __u64 pgtypeinfo_off;    // absolute file offset of .pages.info data
    __u32 flags;             // bit0=0 (no inlined tree), bits1+ = unitSize
};
```

#### Mapping from CodeSignBlock to ioctl arg

| `code_sign_enable_arg` field | Source in parsed code sign block |
|-----|------|
| `version` | 1 (constant) |
| `cs_version` | 2 (constant, page-info support) |
| `hash_algorithm` | `FsVerityInfoSegment.hashAlgorithm` |
| `block_size` | `1 << FsVerityInfoSegment.logBlockSize` (= 4096) |
| `salt_size` | `SignInfo.saltSize` |
| `sig_size` | `SignInfo.sigSize` |
| `pgtypeinfo_size` | `PageInfoExtension.mapSize` (or 0) |
| `salt_ptr` | pointer to `SignInfo.salt` bytes |
| `sig_ptr` | pointer to `SignInfo.signature` bytes (the PKCS#7 DER blob) |
| `data_size` | `SignInfo.dataSize` |
| `tree_offset` | `MerkleTreeExtension.treeOffset` (= 0) |
| `root_hash_ptr` | pointer to `MerkleTreeExtension.rootHash` (64 bytes) |
| `pgtypeinfo_off` | `PageInfoExtension.mapOffset` (absolute file offset) |
| `flags` | `(PageInfoExtension.unitSize << 1)` — bit0=0 since tree is not inlined |

#### JNI implementation

The C function `Java_com_android_apkverify_FsVerityEnabler_enableCodeSign`:

1. Converts the Java `String path` to a C string via `GetStringUTFChars`.
2. Opens the file read-only: `open(path, O_RDONLY)`.
3. Pins Java byte arrays (`salt`, `signature`, `rootHash`) via `GetByteArrayElements`.
   The pinned pointers are valid for the duration of the ioctl.
4. Populates `struct code_sign_enable_arg` with the pinned pointers cast to `__u64`.
5. Calls `ioctl(fd, FS_IOC_ENABLE_CODE_SIGN, &arg)`.
6. Releases all pinned arrays with `JNI_ABORT` (read-only, no copy-back).
7. Closes the file descriptor.
8. Returns 0 on success, `-errno` on failure.

#### What the kernel does

When `FS_IOC_ENABLE_CODE_SIGN` succeeds:

1. The kernel reads the PKCS#7 signature from `sig_ptr` and verifies it against a
   trusted certificate chain (configured in the kernel keyring).
2. The signed data is a 256-byte `FsVerityDescriptor` containing the root hash,
   data size, hash algorithm, and page-info metadata.
3. The kernel computes the Merkle tree over `[0, data_size)` of the file using
   SHA-256 with 4 KiB blocks (same algorithm as `VerityTreeBuilder`).
4. It verifies the computed root hash matches `root_hash_ptr`.
5. If `pgtypeinfo_off != 0`, the kernel reads the page-type bitmap from the file
   at that offset and associates it with the inode for runtime page classification.
6. On every subsequent page fault, the kernel verifies the page's hash against
   the Merkle tree and checks its type against the bitmap.

---

### Build system changes

`build.gradle` now includes `src/apkverify/java` in the main source set and defines
a `runApkVerify` task:

```groovy
sourceSets {
    main {
        java {
            srcDirs 'src/main/java', 'src/apksigner/java', 'src/apkverify/java'
        }
    }
}

tasks.register('runApkVerify', JavaExec) {
    classpath = sourceSets.main.runtimeClasspath
    mainClass = 'com.android.apkverify.ApkVerifyTool'
}
```

The JNI native library (`libfsverity_enable_jni.so`) must be compiled separately
and placed on the library path. It is only needed on OpenHarmony devices with
kernel support for `FS_IOC_ENABLE_CODE_SIGN`.

---

### Tests

| Test class | Tests | Description |
|------------|-------|-------------|
| `internal/codesign/CodeSignBlockTest` | 4 | Build/parse round-trip with and without PageInfoExtension; FsVerityDescriptor digest-byte verification; signature alignment padding |

All 1307 pre-existing tests continue to pass (code signing is opt-in and disabled by
default). The 4 new tests bring the total to 1311.

---

### Output layout example (with code signing enabled)

```
[offset 0]
  LFH  lib/arm64-v8a/libfoo.so   (stored, 16 KiB-aligned)
  DATA  <ELF content>
[offset A]
  LFH  classes.dex               (stored, 4-byte-aligned)
  DATA  <DEX content>
[offset B — 4 KiB-aligned]
  LFH  .pages.info               (stored, 4 KiB-aligned)
  DATA  <bitmap>
[offset C]
  LFH  res/layout/main.xml       (deflated)
  DATA  <compressed content>
[APK Signing Block]
  ├─ V2 signature block (ID 0x7109871a)
  ├─ V3 signature block (ID 0xf05368c0)
  ├─ Code sign block    (ID 0x4F484353)  ← NEW
  └─ Verity padding     (ID 0x42726577)
[Central Directory]
[End of Central Directory]
```

The Merkle tree root hash covers `[0, C)` — the entire LFH section.
The PKCS#7 signature in the code sign block proves the root hash is authentic.
The `.pages.info` bitmap offset (`B + header_size`) is recorded in the
PageInfoExtension so the kernel can find it at runtime.
