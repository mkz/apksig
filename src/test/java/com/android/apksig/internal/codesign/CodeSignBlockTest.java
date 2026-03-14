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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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

    @Test
    public void testBuildAndParseRoundTrip_withNativeLibs() {
        byte[] rootHash = new byte[64];
        rootHash[0] = 0x11;
        byte[] signature = new byte[256];
        signature[0] = 0x30;

        // Create 2 mock .so entries
        byte[] soRootHash1 = new byte[64];
        soRootHash1[0] = (byte) 0xAA;
        soRootHash1[31] = (byte) 0xBB;
        byte[] soSig1 = new byte[200];
        soSig1[0] = 0x31;

        byte[] soRootHash2 = new byte[64];
        soRootHash2[0] = (byte) 0xCC;
        byte[] soSig2 = new byte[180];
        soSig2[0] = 0x32;

        List<NativeLibSignInfo> nativeLibs = new ArrayList<>();
        nativeLibs.add(new NativeLibSignInfo(
                "lib/arm64-v8a/libfoo.so", 65536, 4096, soRootHash1, soSig1));
        nativeLibs.add(new NativeLibSignInfo(
                "lib/arm64-v8a/libbar.so", 32768, 70000, soRootHash2, soSig2));

        byte[] block = CodeSignBlock.build(
                rootHash, signature, 1048576, 8192, 512, nativeLibs);
        assertNotNull(block);

        CodeSignBlockParser parsed = CodeSignBlockParser.parse(block);

        // Verify whole-file fields still work
        assertEquals(1048576, parsed.dataSize);
        assertEquals(0x11, parsed.rootHash[0]);
        assertTrue(parsed.hasPageInfo);

        // Verify native lib entries
        assertEquals(2, parsed.nativeLibCount);
        assertEquals(2, parsed.nativeLibEntries.size());

        CodeSignBlockParser.NativeLibEntry e0 = parsed.nativeLibEntries.get(0);
        assertEquals("lib/arm64-v8a/libfoo.so", e0.fileName);
        assertEquals(65536, e0.dataSize);
        assertEquals(4096, e0.soMapOffset);
        assertEquals(65536, e0.soMapSize);
        assertEquals(200, e0.sigSize);
        assertEquals((byte) 0xAA, e0.rootHash[0]);
        assertEquals((byte) 0xBB, e0.rootHash[31]);
        assertArrayEquals(soSig1, e0.signature);

        CodeSignBlockParser.NativeLibEntry e1 = parsed.nativeLibEntries.get(1);
        assertEquals("lib/arm64-v8a/libbar.so", e1.fileName);
        assertEquals(32768, e1.dataSize);
        assertEquals(70000, e1.soMapOffset);
        assertEquals(32768, e1.soMapSize);
        assertEquals(180, e1.sigSize);
        assertEquals((byte) 0xCC, e1.rootHash[0]);
        assertArrayEquals(soSig2, e1.signature);
    }

    @Test
    public void testBuildAndParseRoundTrip_emptyNativeLibs() {
        byte[] rootHash = new byte[64];
        byte[] signature = new byte[128];

        byte[] block = CodeSignBlock.build(
                rootHash, signature, 4096, 0, 0, Collections.<NativeLibSignInfo>emptyList());

        CodeSignBlockParser parsed = CodeSignBlockParser.parse(block);

        assertEquals(0, parsed.nativeLibCount);
        assertTrue(parsed.nativeLibEntries.isEmpty());
    }

    @Test
    public void testNativeLibSignInfoAlignment() {
        // Test with signatures that are not 4-byte aligned to verify padding
        byte[] soRootHash1 = new byte[64];
        byte[] soSig1 = new byte[131]; // 131 % 4 = 3

        byte[] soRootHash2 = new byte[64];
        soRootHash2[0] = (byte) 0xDD;
        byte[] soSig2 = new byte[129]; // 129 % 4 = 1

        List<NativeLibSignInfo> nativeLibs = new ArrayList<>();
        nativeLibs.add(new NativeLibSignInfo(
                "lib/x86/liba.so", 1000, 500, soRootHash1, soSig1));
        nativeLibs.add(new NativeLibSignInfo(
                "lib/x86/libb.so", 2000, 1500, soRootHash2, soSig2));

        byte[] rootHash = new byte[64];
        byte[] signature = new byte[256];

        byte[] block = CodeSignBlock.build(
                rootHash, signature, 4096, 0, 0, nativeLibs);

        // Verify the segment bytes are 4-byte aligned for SignInfo objects
        byte[] segBytes = CodeSignBlock.buildNativeLibInfoSegment(nativeLibs);
        // segBytes length should be 4-byte aligned overall
        // Each SignInfo offset from the entry table should be 4-byte aligned
        ByteBuffer seg = ByteBuffer.wrap(segBytes).order(ByteOrder.LITTLE_ENDIAN);
        seg.getInt(); // magic
        seg.getInt(); // segmentSize
        int sectionNum = seg.getInt();
        assertEquals(2, sectionNum);

        for (int i = 0; i < sectionNum; i++) {
            int fnOff = seg.getInt();
            int fnSize = seg.getInt();
            int siOff = seg.getInt();
            int siSize = seg.getInt();
            // SignInfo offsets should be 4-byte aligned
            assertEquals("SignInfo offset not 4-byte aligned for entry " + i,
                    0, siOff % 4);
        }

        // Verify round-trip
        CodeSignBlockParser parsed = CodeSignBlockParser.parse(block);
        assertEquals(2, parsed.nativeLibCount);
        assertEquals("lib/x86/liba.so", parsed.nativeLibEntries.get(0).fileName);
        assertEquals("lib/x86/libb.so", parsed.nativeLibEntries.get(1).fileName);
        assertEquals((byte) 0xDD, parsed.nativeLibEntries.get(1).rootHash[0]);
    }
}
