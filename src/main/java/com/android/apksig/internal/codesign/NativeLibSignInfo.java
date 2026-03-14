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
 * Per-native-library signing result for inclusion in the NativeLibInfoSegment.
 */
public final class NativeLibSignInfo {

    private final String fileName;
    private final long dataSize;
    private final long dataOffset;
    private final byte[] rootHash;
    private final byte[] pkcs7Signature;

    public NativeLibSignInfo(
            String fileName,
            long dataSize,
            long dataOffset,
            byte[] rootHash,
            byte[] pkcs7Signature) {
        this.fileName = fileName;
        this.dataSize = dataSize;
        this.dataOffset = dataOffset;
        this.rootHash = rootHash;
        this.pkcs7Signature = pkcs7Signature;
    }

    public String getFileName() {
        return fileName;
    }

    public long getDataSize() {
        return dataSize;
    }

    public long getDataOffset() {
        return dataOffset;
    }

    public byte[] getRootHash() {
        return rootHash;
    }

    public byte[] getPkcs7Signature() {
        return pkcs7Signature;
    }
}
