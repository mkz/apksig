/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.codesign;

import static com.android.apksig.internal.codesign.CodeSignConstants.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Assembles the binary code sign block (without inlined Merkle tree) for embedding in the
 * APK Signing Block.
 *
 * <p>Binary layout:
 * <pre>
 *   CodeSignBlockHeader  (32 bytes)
 *   SegmentHeader[0]     (12 bytes) — FSVERITY_INFO
 *   SegmentHeader[1]     (12 bytes) — HAP_META
 *   SegmentHeader[2]     (12 bytes) — NATIVE_LIB_INFO
 *   FsVerityInfoSegment  (64 bytes)
 *   HapInfoSegment       (variable)
 *   NativeLibInfoSegment (variable)
 * </pre>
 */
public final class CodeSignBlock {

    private CodeSignBlock() {}

    /**
     * Builds the complete code sign block bytes.
     *
     * @param rootHash      64-byte root hash (SHA-256 zero-padded to 64)
     * @param signature     PKCS#7 DER-encoded signature over the FsVerityDescriptor
     * @param dataSize      size of the data covered by the Merkle tree (LFH section)
     * @param mapOffset     absolute file offset of .pages.info data (0 if no bitmap)
     * @param mapSize       size of the .pages.info bitmap data (0 if no bitmap)
     * @param nativeLibs    per-SO signing data (empty list for stub segment)
     * @return the serialized code sign block
     */
    public static byte[] build(
            byte[] rootHash,
            byte[] signature,
            long dataSize,
            long mapOffset,
            long mapSize,
            List<NativeLibSignInfo> nativeLibs) {

        // Compute segment sizes
        int fsVerityInfoSize = FSVERITY_INFO_SEGMENT_SIZE;
        byte[] hapInfoBytes = buildHapInfoSegment(rootHash, signature, dataSize, mapOffset, mapSize);
        int hapInfoSize = hapInfoBytes.length;
        byte[] nativeLibInfoBytes = buildNativeLibInfoSegment(nativeLibs);
        int nativeLibInfoSize = nativeLibInfoBytes.length;

        // Compute offsets (relative to start of code sign block)
        int headersSize = CSB_HEADER_SIZE + CSB_SEGMENT_COUNT * SEGMENT_HEADER_SIZE;
        int fsVerityInfoOffset = headersSize;
        int hapInfoOffset = fsVerityInfoOffset + fsVerityInfoSize;
        int nativeLibInfoOffset = hapInfoOffset + hapInfoSize;
        int totalSize = nativeLibInfoOffset + nativeLibInfoSize;

        ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN);

        // CodeSignBlockHeader (32 bytes)
        buf.putLong(CSB_HEADER_MAGIC);
        buf.putInt(CSB_HEADER_VERSION);
        buf.putInt(totalSize);
        buf.putInt(CSB_SEGMENT_COUNT);
        buf.putInt(0); // flags: no merkle tree inlined
        buf.putLong(0); // reserved

        // SegmentHeader[0]: FSVERITY_INFO
        buf.putInt(CSB_FSVERITY_INFO_SEG);
        buf.putInt(fsVerityInfoOffset);
        buf.putInt(fsVerityInfoSize);

        // SegmentHeader[1]: HAP_META
        buf.putInt(CSB_HAP_META_SEG);
        buf.putInt(hapInfoOffset);
        buf.putInt(hapInfoSize);

        // SegmentHeader[2]: NATIVE_LIB_INFO
        buf.putInt(CSB_NATIVE_LIB_INFO_SEG);
        buf.putInt(nativeLibInfoOffset);
        buf.putInt(nativeLibInfoSize);

        // FsVerityInfoSegment (64 bytes)
        buf.putInt(FSVERITY_INFO_MAGIC);
        buf.put(FSVERITY_INFO_VERSION);
        buf.put(HASH_ALGORITHM_SHA256);
        buf.put(LOG2_BLOCK_SIZE_4096);
        // 57 bytes reserved (zeros)
        buf.position(buf.position() + 57);

        // HapInfoSegment
        buf.put(hapInfoBytes);

        // NativeLibInfoSegment
        buf.put(nativeLibInfoBytes);

        return buf.array();
    }

    /**
     * Backward-compatible overload: no native libs → stub segment.
     */
    public static byte[] build(
            byte[] rootHash,
            byte[] signature,
            long dataSize,
            long mapOffset,
            long mapSize) {
        return build(rootHash, signature, dataSize, mapOffset, mapSize,
                java.util.Collections.<NativeLibSignInfo>emptyList());
    }

    /**
     * Builds the NativeLibInfoSegment.
     *
     * <p>If the list is empty, returns a 12-byte stub (magic + segmentSize + sectionNum=0).
     * Otherwise, builds the full segment with per-SO SignInfo entries.
     */
    static byte[] buildNativeLibInfoSegment(List<NativeLibSignInfo> nativeLibs) {
        if (nativeLibs == null || nativeLibs.isEmpty()) {
            ByteBuffer stub = ByteBuffer.allocate(NATIVE_LIB_INFO_STUB_SIZE)
                    .order(ByteOrder.LITTLE_ENDIAN);
            stub.putInt(NATIVE_LIB_INFO_MAGIC);
            stub.putInt(NATIVE_LIB_INFO_STUB_SIZE);
            stub.putInt(0); // sectionNum = 0
            return stub.array();
        }

        int sectionNum = nativeLibs.size();

        // Pre-compute filename bytes
        byte[][] fileNameBytes = new byte[sectionNum][];
        int totalFileNameSize = 0;
        for (int i = 0; i < sectionNum; i++) {
            fileNameBytes[i] = nativeLibs.get(i).getFileName().getBytes(StandardCharsets.UTF_8);
            totalFileNameSize += fileNameBytes[i].length;
        }
        int fileNamePadding = (SIGNATURE_ALIGNMENT - (totalFileNameSize % SIGNATURE_ALIGNMENT))
                % SIGNATURE_ALIGNMENT;

        // Pre-compute per-SO SignInfo blocks
        byte[][] signInfoBlocks = new byte[sectionNum][];
        for (int i = 0; i < sectionNum; i++) {
            signInfoBlocks[i] = buildPerSoSignInfo(nativeLibs.get(i));
        }

        // Layout:
        //   Header: 12 bytes (magic + segmentSize + sectionNum)
        //   Entry table: sectionNum * 16 bytes
        //   Filenames: totalFileNameSize + fileNamePadding
        //   SignInfo blocks: sum of signInfoBlocks lengths
        int headerSize = 12;
        int entryTableSize = sectionNum * NATIVE_LIB_ENTRY_SIZE;
        int fileNamesBlockSize = totalFileNameSize + fileNamePadding;

        int totalSignInfoSize = 0;
        for (byte[] si : signInfoBlocks) {
            totalSignInfoSize += si.length;
        }

        int segmentSize = headerSize + entryTableSize + fileNamesBlockSize + totalSignInfoSize;

        ByteBuffer buf = ByteBuffer.allocate(segmentSize).order(ByteOrder.LITTLE_ENDIAN);

        // Header
        buf.putInt(NATIVE_LIB_INFO_MAGIC);
        buf.putInt(segmentSize);
        buf.putInt(sectionNum);

        // Entry table — compute offsets relative to segment start
        int fileNameOffset = headerSize + entryTableSize;
        int signInfoOffset = headerSize + entryTableSize + fileNamesBlockSize;

        for (int i = 0; i < sectionNum; i++) {
            buf.putInt(fileNameOffset);              // fileNameOffset
            buf.putInt(fileNameBytes[i].length);     // fileNameSize
            buf.putInt(signInfoOffset);              // signInfoOffset
            buf.putInt(signInfoBlocks[i].length);    // signInfoSize
            fileNameOffset += fileNameBytes[i].length;
            signInfoOffset += signInfoBlocks[i].length;
        }

        // Filenames (concatenated, no null terminators)
        for (byte[] fn : fileNameBytes) {
            buf.put(fn);
        }
        // Padding to 4-byte alignment
        if (fileNamePadding > 0) {
            buf.position(buf.position() + fileNamePadding);
        }

        // SignInfo blocks
        for (byte[] si : signInfoBlocks) {
            buf.put(si);
        }

        return buf.array();
    }

    /**
     * Builds a per-SO SignInfo with MerkleTreeExtension and PageInfoExtension.
     */
    private static byte[] buildPerSoSignInfo(NativeLibSignInfo lib) {
        int sigSize = lib.getPkcs7Signature().length;
        int sigPadding = (SIGNATURE_ALIGNMENT - (sigSize % SIGNATURE_ALIGNMENT))
                % SIGNATURE_ALIGNMENT;

        int merkleTreeExtSize = EXTENSION_HEADER_SIZE + MERKLE_TREE_EXTENSION_DATA_SIZE; // 88
        int pageInfoExtSize = EXTENSION_HEADER_SIZE + PAGE_INFO_EXT_DATA_SIZE_WITHOUT_SIGN; // 32

        int extensionOffset = SIGN_INFO_FIXED_SIZE + sigSize + sigPadding;
        int totalSize = extensionOffset + merkleTreeExtSize + pageInfoExtSize;

        ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN);

        // SignInfo fixed header
        buf.putInt(0);                          // saltSize = 0
        buf.putInt(sigSize);                    // sigSize
        buf.putInt(FLAG_MERKLE_TREE_INCLUDED);  // flags
        buf.putLong(lib.getDataSize());         // dataSize
        // salt (32 bytes of zeros)
        buf.position(buf.position() + SALT_SIZE);
        buf.putInt(2);                          // extensionNum = 2
        buf.putInt(extensionOffset);            // extensionOffset
        // signature
        buf.put(lib.getPkcs7Signature());
        // alignment padding
        if (sigPadding > 0) {
            buf.position(buf.position() + sigPadding);
        }

        // MerkleTreeExtension (88 bytes)
        buf.putInt(EXT_TYPE_MERKLE_TREE);
        buf.putInt(MERKLE_TREE_EXTENSION_DATA_SIZE);
        buf.putLong(0); // treeSize = 0
        buf.putLong(0); // treeOffset = 0
        byte[] rootHash = lib.getRootHash();
        buf.put(rootHash, 0, Math.min(rootHash.length, ROOT_HASH_SIZE));
        if (rootHash.length < ROOT_HASH_SIZE) {
            buf.position(buf.position() + (ROOT_HASH_SIZE - rootHash.length));
        }

        // PageInfoExtension (32 bytes)
        buf.putInt(EXT_TYPE_PAGE_INFO);
        buf.putInt(PAGE_INFO_EXT_DATA_SIZE_WITHOUT_SIGN);
        buf.putLong(lib.getDataOffset());   // mapOffset = absolute data offset of .so
        buf.putLong(lib.getDataSize());     // mapSize = .so uncompressed size
        buf.put((byte) 0);                 // unitSize = 0
        buf.position(buf.position() + 3);  // reserved
        buf.putInt(0);                      // signSize = 0

        return buf.array();
    }

    /**
     * Builds the HapInfoSegment: magic + SignInfo + extensions.
     */
    private static byte[] buildHapInfoSegment(
            byte[] rootHash,
            byte[] signature,
            long dataSize,
            long mapOffset,
            long mapSize) {

        // Compute SignInfo fields
        int sigSize = signature.length;
        int sigPadding = (SIGNATURE_ALIGNMENT - (sigSize % SIGNATURE_ALIGNMENT)) % SIGNATURE_ALIGNMENT;

        // Extensions: always MerkleTreeExtension; PageInfoExtension if bitmap present
        boolean hasPageInfo = mapSize > 0;
        int extensionNum = hasPageInfo ? 2 : 1;

        int merkleTreeExtSize = EXTENSION_HEADER_SIZE + MERKLE_TREE_EXTENSION_DATA_SIZE; // 88
        int pageInfoExtSize = 0;
        if (hasPageInfo) {
            // type(4) + size(4) + mapOffset(8) + mapSize(8) + unitSize(1) + reserved(3) + signSize(4) = 32
            pageInfoExtSize = EXTENSION_HEADER_SIZE + PAGE_INFO_EXT_DATA_SIZE_WITHOUT_SIGN;
        }

        // extensionOffset = offset from start of SignInfo to first extension
        int extensionOffset = SIGN_INFO_FIXED_SIZE + sigSize + sigPadding;
        int signInfoTotalSize = extensionOffset + merkleTreeExtSize + pageInfoExtSize;

        // HapInfoSegment = magic(4) + signInfoTotalSize
        int hapInfoSize = 4 + signInfoTotalSize;

        ByteBuffer buf = ByteBuffer.allocate(hapInfoSize).order(ByteOrder.LITTLE_ENDIAN);

        // HapInfoSegment magic
        buf.putInt(HAP_INFO_MAGIC);

        // SignInfo
        buf.putInt(0);          // saltSize = 0
        buf.putInt(sigSize);    // sigSize
        buf.putInt(0);          // flags: no merkle tree inlined
        buf.putLong(dataSize);  // dataSize
        // salt (32 bytes of zeros)
        buf.position(buf.position() + SALT_SIZE);
        buf.putInt(extensionNum);
        buf.putInt(extensionOffset);
        // signature
        buf.put(signature);
        // alignment padding
        if (sigPadding > 0) {
            buf.position(buf.position() + sigPadding);
        }

        // MerkleTreeExtension (88 bytes)
        buf.putInt(EXT_TYPE_MERKLE_TREE);
        buf.putInt(MERKLE_TREE_EXTENSION_DATA_SIZE); // data size (excluding header)
        buf.putLong(0); // merkleTreeSize = 0 (not inlined)
        buf.putLong(0); // merkleTreeOffset = 0 (kernel computes)
        // rootHash (64 bytes)
        buf.put(rootHash, 0, Math.min(rootHash.length, ROOT_HASH_SIZE));
        if (rootHash.length < ROOT_HASH_SIZE) {
            buf.position(buf.position() + (ROOT_HASH_SIZE - rootHash.length));
        }

        // PageInfoExtension (if present)
        if (hasPageInfo) {
            buf.putInt(EXT_TYPE_PAGE_INFO);
            buf.putInt(PAGE_INFO_EXT_DATA_SIZE_WITHOUT_SIGN);
            buf.putLong(mapOffset);
            buf.putLong(mapSize);
            buf.put(PAGE_INFO_DEFAULT_UNIT_SIZE);
            buf.position(buf.position() + 3); // reserved
            buf.putInt(0); // signSize = 0 (page info signature not implemented yet)
        }

        return buf.array();
    }
}
