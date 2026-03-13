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

import static org.junit.Assert.*;

import com.android.apkverify.CodeSignBlockParser;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Unit tests for {@link CodeSignBlock} build and {@link CodeSignBlockParser} parse round-trip.
 */
public class CodeSignBlockTest {

    @Test
    public void testBuildAndParseRoundTrip_withPageInfo() {
        // Prepare test data
        byte[] rootHash = new byte[64];
        for (int i = 0; i < 32; i++) {
            rootHash[i] = (byte) (i + 1);
        }
        byte[] signature = new byte[256];
        for (int i = 0; i < signature.length; i++) {
            signature[i] = (byte) (i & 0xFF);
        }
        long dataSize = 1024 * 1024; // 1 MB
        long mapOffset = 8192;
        long mapSize = 512;

        // Build
        byte[] block = CodeSignBlock.build(rootHash, signature, dataSize, mapOffset, mapSize);
        assertNotNull(block);
        assertTrue(block.length > 0);

        // Verify header magic
        ByteBuffer buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(CodeSignConstants.CSB_HEADER_MAGIC, buf.getLong());

        // Parse
        CodeSignBlockParser parsed = CodeSignBlockParser.parse(block);

        // Verify parsed fields
        assertEquals(CodeSignConstants.HASH_ALGORITHM_SHA256, parsed.hashAlgorithm);
        assertEquals(CodeSignConstants.LOG2_BLOCK_SIZE_4096, parsed.logBlockSize);
        assertEquals(dataSize, parsed.dataSize);
        assertEquals(signature.length, parsed.sigSize);
        assertArrayEquals(signature, parsed.signature);
        assertEquals(0, parsed.merkleTreeOffset);
        assertEquals(0, parsed.merkleTreeSize);
        assertNotNull(parsed.rootHash);
        // Verify root hash matches
        for (int i = 0; i < 32; i++) {
            assertEquals("rootHash[" + i + "]", (byte) (i + 1), parsed.rootHash[i]);
        }
        for (int i = 32; i < 64; i++) {
            assertEquals("rootHash[" + i + "]", 0, parsed.rootHash[i]);
        }

        // Verify page info
        assertTrue(parsed.hasPageInfo);
        assertEquals(mapOffset, parsed.pageInfoMapOffset);
        assertEquals(mapSize, parsed.pageInfoMapSize);
        assertEquals(CodeSignConstants.PAGE_INFO_DEFAULT_UNIT_SIZE, parsed.pageInfoUnitSize);
    }

    @Test
    public void testBuildAndParseRoundTrip_withoutPageInfo() {
        byte[] rootHash = new byte[64];
        rootHash[0] = 0x42;
        byte[] signature = new byte[128];
        signature[0] = 0x30;
        long dataSize = 4096;

        byte[] block = CodeSignBlock.build(rootHash, signature, dataSize, 0, 0);
        assertNotNull(block);

        CodeSignBlockParser parsed = CodeSignBlockParser.parse(block);

        assertEquals(CodeSignConstants.HASH_ALGORITHM_SHA256, parsed.hashAlgorithm);
        assertEquals(dataSize, parsed.dataSize);
        assertEquals(signature.length, parsed.sigSize);
        assertArrayEquals(signature, parsed.signature);
        assertEquals(0x42, parsed.rootHash[0]);
        assertFalse(parsed.hasPageInfo);
    }

    @Test
    public void testFsVerityDescriptorDigestBytes() {
        byte[] rootHash = new byte[64];
        rootHash[0] = (byte) 0xAA;
        byte[] salt = new byte[32];
        long dataSize = 1048576;
        long mapOffset = 4096;
        long mapSize = 256;

        FsVerityDescriptor descriptor = new FsVerityDescriptor(
                CodeSignConstants.HASH_ALGORITHM_SHA256,
                CodeSignConstants.LOG2_BLOCK_SIZE_4096,
                (byte) 0,
                dataSize,
                rootHash,
                salt,
                0,
                0,
                mapOffset,
                mapSize,
                CodeSignConstants.PAGE_INFO_DEFAULT_UNIT_SIZE);

        byte[] digestBytes = descriptor.getDigestBytes();
        assertEquals(256, digestBytes.length);

        ByteBuffer buf = ByteBuffer.wrap(digestBytes).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(CodeSignConstants.DESCRIPTOR_VERSION, buf.get()); // version
        assertEquals(CodeSignConstants.HASH_ALGORITHM_SHA256, buf.get()); // hashAlgorithm
        assertEquals(CodeSignConstants.LOG2_BLOCK_SIZE_4096, buf.get()); // log2BlockSize
        assertEquals(0, buf.get()); // saltSize
        assertEquals(0, buf.getInt()); // signSize = 0 (digest form)
        assertEquals(dataSize, buf.getLong()); // dataSize

        // rootHash at offset 16
        assertEquals((byte) 0xAA, digestBytes[16]);

        // flags at offset 112: (unitSize << 1) | 0 = 4 << 1 = 8
        buf.position(112);
        assertEquals(8, buf.getInt());

        // mapSize at offset 116
        assertEquals((int) mapSize, buf.getInt());

        // csVersion at offset 255
        assertEquals(CodeSignConstants.CODE_SIGN_VERSION_V2, digestBytes[255]);
    }

    @Test
    public void testSignatureAlignmentPadding() {
        // Test with a signature whose size is not 4-byte aligned
        byte[] rootHash = new byte[64];
        byte[] signature = new byte[131]; // 131 % 4 = 3, needs 1 byte padding
        long dataSize = 4096;

        byte[] block = CodeSignBlock.build(rootHash, signature, dataSize, 0, 0);
        CodeSignBlockParser parsed = CodeSignBlockParser.parse(block);

        assertEquals(131, parsed.sigSize);
        assertEquals(dataSize, parsed.dataSize);
        assertNotNull(parsed.rootHash);
    }
}
