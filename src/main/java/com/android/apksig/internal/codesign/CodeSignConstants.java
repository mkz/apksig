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

/**
 * Constants for the OpenHarmony-compatible code sign block embedded in the APK Signing Block.
 */
public final class CodeSignConstants {

    private CodeSignConstants() {}

    /** APK Signing Block ID for the code sign block ("OHCS" in ASCII). */
    public static final int APK_CODE_SIGN_BLOCK_ID = 0x4F484353;

    // --- CodeSignBlockHeader ---
    /** Magic number for the code sign block header. */
    public static final long CSB_HEADER_MAGIC = 0x5389FCCDE046C8C6L;
    public static final int CSB_HEADER_VERSION = 1;
    public static final int CSB_SEGMENT_COUNT = 3;
    /** Flag: Merkle tree is stored inline in the code sign block. */
    public static final int FLAG_MERKLE_TREE_INLINED = 0x1;

    // --- Segment types ---
    public static final int CSB_FSVERITY_INFO_SEG = 0x1;
    public static final int CSB_HAP_META_SEG = 0x2;
    public static final int CSB_NATIVE_LIB_INFO_SEG = 0x3;

    // --- FsVerityInfoSegment ---
    public static final int FSVERITY_INFO_MAGIC = 0x31AB1E38;
    public static final byte FSVERITY_INFO_VERSION = 1;
    public static final byte HASH_ALGORITHM_SHA256 = 1;
    public static final byte LOG2_BLOCK_SIZE_4096 = 12;
    /** Total size of the FsVerityInfoSegment: 4 (magic) + 3 (version/algo/blocksize) + 57 (reserved) = 64. */
    public static final int FSVERITY_INFO_SEGMENT_SIZE = 64;

    // --- HapInfoSegment ---
    public static final int HAP_INFO_MAGIC = 0xCC66C1B5;

    // --- SignInfo ---
    public static final int SIGN_INFO_FIXED_SIZE = 60;
    public static final int SIGNATURE_ALIGNMENT = 4;
    public static final int SALT_SIZE = 32;
    public static final int SIGN_INFO_FLAG_MERKLE_TREE = 0x1;

    // --- Extensions ---
    public static final int EXTENSION_HEADER_SIZE = 8;
    public static final int EXT_TYPE_MERKLE_TREE = 0x1;
    public static final int EXT_TYPE_PAGE_INFO = 0x2;
    public static final int MERKLE_TREE_EXTENSION_DATA_SIZE = 80;
    public static final int ROOT_HASH_SIZE = 64;
    public static final int PAGE_INFO_EXT_DATA_SIZE_WITHOUT_SIGN = 24;
    public static final byte PAGE_INFO_DEFAULT_UNIT_SIZE = 4;

    // --- NativeLibInfoSegment ---
    public static final int NATIVE_LIB_INFO_MAGIC = 0x0ED2E720;
    public static final int NATIVE_LIB_INFO_STUB_SIZE = 12;
    /** Size of each entry in the NativeLibInfoSegment entry table. */
    public static final int NATIVE_LIB_ENTRY_SIZE = 16;
    /** SignInfo flag: Merkle tree root hash is included. */
    public static final int FLAG_MERKLE_TREE_INCLUDED = 0x1;

    // --- FsVerityDescriptor ---
    public static final int DESCRIPTOR_SIZE = 256;
    public static final byte DESCRIPTOR_VERSION = 1;
    public static final byte CODE_SIGN_VERSION_V2 = 0x2;

    // --- SegmentHeader ---
    public static final int SEGMENT_HEADER_SIZE = 12;

    // --- CodeSignBlockHeader total ---
    /** 8 (magic) + 4*4 (version, blockSize, segmentNum, flags) + 8 (reserved) = 32. */
    public static final int CSB_HEADER_SIZE = 32;
}
