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
 * Java mirror of the OpenHarmony kernel {@code struct code_sign_enable_arg}.
 * Passed to the JNI layer for the {@code FS_IOC_ENABLE_CODE_SIGN} ioctl.
 */
public final class CodeSignEnableArg {
    /** struct version, must be 1. */
    public int version = 1;
    /** Code sign version: 2 for page info support. */
    public int csVersion = 2;
    /** Hash algorithm: 1 = SHA-256. */
    public int hashAlgorithm = 1;
    /** Block size in bytes: 4096. */
    public int blockSize = 4096;

    /** Salt size in bytes (may be 0). */
    public int saltSize;
    /** PKCS#7 signature size in bytes. */
    public int sigSize;
    /** Page type info bitmap size in bytes (0 if no bitmap). */
    public int pgtypeinfoSize;

    /** Salt bytes (may be null if saltSize == 0). */
    public byte[] salt;
    /** PKCS#7 signature bytes. */
    public byte[] signature;
    /** Data size covered by the Merkle tree (LFH section size). */
    public long dataSize;
    /** Merkle tree offset in the file (0 = kernel computes tree). */
    public long treeOffset;
    /** 64-byte root hash. */
    public byte[] rootHash;
    /** Absolute file offset of .pages.info bitmap data. */
    public long pgtypeinfoOff;
    /** Flags: bit0 = merkle tree inlined, bits 1+ = unitSize. */
    public int flags;
}
