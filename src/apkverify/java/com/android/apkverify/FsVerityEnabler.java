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

/**
 * JNI wrapper for enabling fs-verity code signing on a file via
 * {@code ioctl(fd, FS_IOC_ENABLE_CODE_SIGN, &arg)}.
 *
 * <p>The native library {@code libfsverity_enable_jni} must be on the library path.
 */
public final class FsVerityEnabler {

    static {
        System.loadLibrary("fsverity_enable_jni");
    }

    /**
     * Enables code signing on the file at {@code path}.
     *
     * @param path         absolute path to the file
     * @param version      struct version (1)
     * @param csVersion    code sign version (2)
     * @param hashAlgorithm hash algorithm (1 = SHA-256)
     * @param blockSize    block size (4096)
     * @param salt         salt bytes (may be empty)
     * @param signature    PKCS#7 signature bytes
     * @param dataSize     data size covered by Merkle tree
     * @param treeOffset   Merkle tree offset (0 = kernel computes)
     * @param rootHash     64-byte root hash
     * @param pgtypeinfoOff absolute offset of .pages.info data
     * @param pgtypeinfoSize bitmap size
     * @param flags        flags (unitSize << 1, bit0=0)
     * @return 0 on success, negative errno on failure
     */
    public static native int enableCodeSign(
            String path,
            int version,
            int csVersion,
            int hashAlgorithm,
            int blockSize,
            byte[] salt,
            byte[] signature,
            long dataSize,
            long treeOffset,
            byte[] rootHash,
            long pgtypeinfoOff,
            int pgtypeinfoSize,
            int flags);
}
