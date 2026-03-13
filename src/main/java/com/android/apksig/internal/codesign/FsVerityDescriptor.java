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

/**
 * 256-byte fs-verity descriptor, compatible with OpenHarmony's FsVerityDescriptor.
 *
 * <p>Layout (little-endian):
 * <pre>
 * offset  size  field
 *   0      1    version
 *   1      1    hashAlgorithm
 *   2      1    log2BlockSize
 *   3      1    saltSize
 *   4      4    signSize
 *   8      8    dataSize
 *  16     64    rootHash
 *  80     32    salt
 * 112      4    flags
 * 116      4    reserved / mapSize (csv2)
 * 120      8    merkleTreeOffset
 * 128      8    mapOffset (csv2) / reserved
 * 136    119    reserved
 * 255      1    csVersion
 * </pre>
 */
public final class FsVerityDescriptor {

    private final byte hashAlgorithm;
    private final byte log2BlockSize;
    private final byte saltSize;
    private final long dataSize;
    private final byte[] rootHash;
    private final byte[] salt;
    private final int flags;
    private final long merkleTreeOffset;
    private final long mapOffset;
    private final long mapSize;
    private final byte unitSize;

    public FsVerityDescriptor(
            byte hashAlgorithm,
            byte log2BlockSize,
            byte saltSize,
            long dataSize,
            byte[] rootHash,
            byte[] salt,
            int flags,
            long merkleTreeOffset,
            long mapOffset,
            long mapSize,
            byte unitSize) {
        this.hashAlgorithm = hashAlgorithm;
        this.log2BlockSize = log2BlockSize;
        this.saltSize = saltSize;
        this.dataSize = dataSize;
        this.rootHash = rootHash;
        this.salt = salt;
        this.flags = flags;
        this.merkleTreeOffset = merkleTreeOffset;
        this.mapOffset = mapOffset;
        this.mapSize = mapSize;
        this.unitSize = unitSize;
    }

    /**
     * Returns the 256-byte descriptor for PKCS#7 signing (csVersion=2, signSize=0).
     *
     * <p>This is the "digest" form: signSize is zeroed because it's the data being signed.
     */
    public byte[] getDigestBytes() {
        ByteBuffer buf = ByteBuffer.allocate(DESCRIPTOR_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(DESCRIPTOR_VERSION);
        buf.put(hashAlgorithm);
        buf.put(log2BlockSize);
        buf.put(saltSize);
        buf.putInt(0); // signSize = 0 for digest
        buf.putLong(dataSize);
        writePadded(buf, rootHash, ROOT_HASH_SIZE);
        writePadded(buf, salt, SALT_SIZE);
        buf.putInt((unitSize << 1) | flags);
        buf.putInt((int) mapSize); // mapSize at offset 116
        buf.putLong(merkleTreeOffset);
        buf.putLong(mapOffset);
        // remaining 119 bytes are zeros (buffer is pre-zeroed)
        buf.position(DESCRIPTOR_SIZE - 1);
        buf.put(CODE_SIGN_VERSION_V2);
        return buf.array();
    }

    private static void writePadded(ByteBuffer buf, byte[] data, int fieldSize) {
        int pos = buf.position();
        if (data != null) {
            buf.put(data, 0, Math.min(data.length, fieldSize));
        }
        buf.position(pos + fieldSize);
    }
}
