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

package com.android.apkverify;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Parses a binary code sign block (as produced by
 * {@link com.android.apksig.internal.codesign.CodeSignBlock}).
 *
 * <p>Extracts FsVerityInfo, SignInfo (salt, signature, dataSize), and extensions
 * (MerkleTreeExtension, PageInfoExtension).
 */
public final class CodeSignBlockParser {

    // CodeSignBlockHeader
    private static final long CSB_HEADER_MAGIC = 0x5389FCCDE046C8C6L;

    // Segment types
    private static final int SEG_FSVERITY_INFO = 0x1;
    private static final int SEG_HAP_META = 0x2;
    private static final int SEG_NATIVE_LIB_INFO = 0x3;

    // FsVerityInfoSegment magic
    private static final int FSVERITY_INFO_MAGIC = 0x31AB1E38;

    // HapInfoSegment magic
    private static final int HAP_INFO_MAGIC = 0xCC66C1B5;

    // Extension types
    private static final int EXT_MERKLE_TREE = 0x1;
    private static final int EXT_PAGE_INFO = 0x2;

    // Parsed fields
    public byte hashAlgorithm;
    public byte logBlockSize;

    public int saltSize;
    public int sigSize;
    public int signInfoFlags;
    public long dataSize;
    public byte[] salt;
    public byte[] signature;

    public long merkleTreeSize;
    public long merkleTreeOffset;
    public byte[] rootHash;

    public boolean hasPageInfo;
    public long pageInfoMapOffset;
    public long pageInfoMapSize;
    public byte pageInfoUnitSize;

    private CodeSignBlockParser() {}

    /**
     * Parses the given code sign block bytes.
     *
     * @param blockBytes raw bytes of the code sign block (value from APK Signing Block pair)
     * @return parsed result
     * @throws IllegalArgumentException if the block is malformed
     */
    public static CodeSignBlockParser parse(byte[] blockBytes) {
        ByteBuffer buf = ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN);
        CodeSignBlockParser result = new CodeSignBlockParser();

        // CodeSignBlockHeader (32 bytes)
        long magic = buf.getLong();
        if (magic != CSB_HEADER_MAGIC) {
            throw new IllegalArgumentException(
                    "Bad code sign block magic: 0x" + Long.toHexString(magic));
        }
        int version = buf.getInt();
        int blockSize = buf.getInt();
        int segmentNum = buf.getInt();
        int flags = buf.getInt();
        buf.getLong(); // reserved

        // Segment headers
        int[] segTypes = new int[segmentNum];
        int[] segOffsets = new int[segmentNum];
        int[] segSizes = new int[segmentNum];
        for (int i = 0; i < segmentNum; i++) {
            segTypes[i] = buf.getInt();
            segOffsets[i] = buf.getInt();
            segSizes[i] = buf.getInt();
        }

        // Parse each segment
        for (int i = 0; i < segmentNum; i++) {
            buf.position(segOffsets[i]);
            switch (segTypes[i]) {
                case SEG_FSVERITY_INFO:
                    parseFsVerityInfoSegment(buf, result);
                    break;
                case SEG_HAP_META:
                    parseHapInfoSegment(buf, segSizes[i], result);
                    break;
                case SEG_NATIVE_LIB_INFO:
                    // Stub segment, skip
                    break;
            }
        }

        return result;
    }

    private static void parseFsVerityInfoSegment(ByteBuffer buf, CodeSignBlockParser result) {
        int fsMagic = buf.getInt();
        if (fsMagic != FSVERITY_INFO_MAGIC) {
            throw new IllegalArgumentException(
                    "Bad FsVerityInfo magic: 0x" + Integer.toHexString(fsMagic));
        }
        result.hashAlgorithm = buf.get(); // version field is hashAlgorithm? No, version first
        // Actually: magic(4), version(1), hashAlgorithm(1), logBlockSize(1), reserved(57)
        // We already read magic. Re-read:
        // The layout in CodeSignBlock.build() is:
        //   putInt(FSVERITY_INFO_MAGIC), put(version), put(hashAlg), put(logBlockSize), skip 57
        // But we already read 4 bytes as fsMagic. The next byte is version.
        // result.hashAlgorithm was set to version byte. Fix:
        byte fsVersion = result.hashAlgorithm; // this was actually version
        result.hashAlgorithm = buf.get();
        result.logBlockSize = buf.get();
        // Skip remaining reserved bytes (57)
    }

    private static void parseHapInfoSegment(
            ByteBuffer buf, int segSize, CodeSignBlockParser result) {
        int hapMagic = buf.getInt();
        if (hapMagic != HAP_INFO_MAGIC) {
            throw new IllegalArgumentException(
                    "Bad HapInfo magic: 0x" + Integer.toHexString(hapMagic));
        }

        // SignInfo
        result.saltSize = buf.getInt();
        result.sigSize = buf.getInt();
        result.signInfoFlags = buf.getInt();
        result.dataSize = buf.getLong();
        result.salt = new byte[32];
        buf.get(result.salt);
        int extensionNum = buf.getInt();
        int extensionOffset = buf.getInt();

        // Signature
        result.signature = new byte[result.sigSize];
        buf.get(result.signature);

        // Skip alignment padding to reach extensions
        // extensionOffset is relative to start of SignInfo (= hapMagic position + 4)
        // We need to jump to the right position for extensions.
        // The SignInfo starts at hapMagic+4. extensionOffset is from there.
        // Current position should be near extensionOffset, but may need alignment skip.
        // Just parse extensions sequentially from here, accounting for padding.

        // Align to 4 bytes after signature
        int sigEnd = buf.position();
        int padding = (4 - (result.sigSize % 4)) % 4;
        buf.position(sigEnd + padding);

        // Parse extensions
        for (int i = 0; i < extensionNum; i++) {
            int extType = buf.getInt();
            int extDataSize = buf.getInt();
            int extDataStart = buf.position();
            switch (extType) {
                case EXT_MERKLE_TREE:
                    result.merkleTreeSize = buf.getLong();
                    result.merkleTreeOffset = buf.getLong();
                    result.rootHash = new byte[64];
                    buf.get(result.rootHash);
                    break;
                case EXT_PAGE_INFO:
                    result.hasPageInfo = true;
                    result.pageInfoMapOffset = buf.getLong();
                    result.pageInfoMapSize = buf.getLong();
                    result.pageInfoUnitSize = buf.get();
                    buf.get(new byte[3]); // reserved
                    buf.getInt(); // signSize (unused for now)
                    break;
                default:
                    // Unknown extension, skip
                    break;
            }
            buf.position(extDataStart + extDataSize);
        }
    }
}
