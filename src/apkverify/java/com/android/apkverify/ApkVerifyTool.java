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

import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtilsLite;
import com.android.apksig.internal.apk.SignatureNotFoundException;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.zip.ZipSections;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;

/**
 * CLI tool that reads a code sign block from a signed APK and enables fs-verity
 * code signing via the {@code FS_IOC_ENABLE_CODE_SIGN} ioctl.
 *
 * <p>Usage: {@code java -cp ... com.android.apkverify.ApkVerifyTool <apk-path>}
 */
public final class ApkVerifyTool {

    private static final int APK_CODE_SIGN_BLOCK_ID = 0x4F484353;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: ApkVerifyTool <apk-path> [--dry-run]");
            System.exit(1);
        }
        String apkPath = args[0];
        boolean dryRun = args.length > 1 && "--dry-run".equals(args[1]);

        File apkFile = new File(apkPath);
        if (!apkFile.exists()) {
            System.err.println("APK not found: " + apkPath);
            System.exit(1);
        }

        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            DataSource apk = DataSources.asDataSource(raf);

            // Find ZIP sections
            com.android.apksig.zip.ZipFormatException zipError = null;
            ApkUtils.ZipSections zipSections;
            try {
                zipSections = ApkUtils.findZipSections(apk);
            } catch (com.android.apksig.zip.ZipFormatException e) {
                System.err.println("Not a valid ZIP/APK: " + e.getMessage());
                System.exit(1);
                return;
            }

            // Find APK Signing Block
            ApkUtils.ApkSigningBlock signingBlock;
            try {
                signingBlock = ApkUtils.findApkSigningBlock(apk, zipSections);
            } catch (com.android.apksig.apk.ApkSigningBlockNotFoundException e) {
                System.err.println("No APK Signing Block found: " + e.getMessage());
                System.exit(1);
                return;
            }

            // Find the code sign block by ID
            ByteBuffer codeSignBlockBuf;
            try {
                codeSignBlockBuf = ApkSigningBlockUtilsLite.findApkSignatureSchemeBlock(
                        signingBlock.getContents().getByteBuffer(
                                0, (int) signingBlock.getContents().size()),
                        APK_CODE_SIGN_BLOCK_ID);
            } catch (SignatureNotFoundException e) {
                System.err.println("No code sign block (ID 0x4F484353) in APK Signing Block");
                System.exit(1);
                return;
            }

            byte[] blockBytes = new byte[codeSignBlockBuf.remaining()];
            codeSignBlockBuf.get(blockBytes);

            // Parse the code sign block
            CodeSignBlockParser parsed = CodeSignBlockParser.parse(blockBytes);

            System.out.println("Code sign block parsed successfully:");
            System.out.println("  hashAlgorithm: " + parsed.hashAlgorithm);
            System.out.println("  logBlockSize: " + parsed.logBlockSize);
            System.out.println("  dataSize: " + parsed.dataSize);
            System.out.println("  sigSize: " + parsed.sigSize);
            System.out.println("  rootHash: " + bytesToHex(parsed.rootHash, 32));
            System.out.println("  merkleTreeOffset: " + parsed.merkleTreeOffset);
            System.out.println("  merkleTreeSize: " + parsed.merkleTreeSize);
            if (parsed.hasPageInfo) {
                System.out.println("  pageInfo.mapOffset: " + parsed.pageInfoMapOffset);
                System.out.println("  pageInfo.mapSize: " + parsed.pageInfoMapSize);
                System.out.println("  pageInfo.unitSize: " + parsed.pageInfoUnitSize);
            }

            // Print per-SO native lib info
            if (parsed.nativeLibCount > 0) {
                System.out.println("  nativeLibCount: " + parsed.nativeLibCount);
                for (CodeSignBlockParser.NativeLibEntry entry : parsed.nativeLibEntries) {
                    System.out.println("  nativeLib: " + entry.fileName);
                    System.out.println("    dataSize: " + entry.dataSize);
                    System.out.println("    soMapOffset: " + entry.soMapOffset);
                    System.out.println("    soMapSize: " + entry.soMapSize);
                    System.out.println("    rootHash: " + bytesToHex(entry.rootHash, 32));
                    System.out.println("    sigSize: " + entry.sigSize);
                }
            }

            if (dryRun) {
                System.out.println("Dry run — not calling ioctl.");
                return;
            }

            // Build whole-file ioctl arg
            CodeSignEnableArg arg = new CodeSignEnableArg();
            arg.hashAlgorithm = parsed.hashAlgorithm;
            arg.blockSize = 1 << parsed.logBlockSize;
            arg.saltSize = parsed.saltSize;
            arg.salt = parsed.salt;
            arg.sigSize = parsed.sigSize;
            arg.signature = parsed.signature;
            arg.dataSize = parsed.dataSize;
            arg.treeOffset = parsed.merkleTreeOffset;
            arg.rootHash = parsed.rootHash;
            if (parsed.hasPageInfo) {
                arg.pgtypeinfoOff = parsed.pageInfoMapOffset;
                arg.pgtypeinfoSize = (int) parsed.pageInfoMapSize;
                arg.flags = (parsed.pageInfoUnitSize << 1); // bit0 = 0 (no inlined tree)
            }

            int ret = FsVerityEnabler.enableCodeSign(
                    apkPath,
                    arg.version,
                    arg.csVersion,
                    arg.hashAlgorithm,
                    arg.blockSize,
                    arg.salt != null ? arg.salt : new byte[0],
                    arg.signature,
                    arg.dataSize,
                    arg.treeOffset,
                    arg.rootHash,
                    arg.pgtypeinfoOff,
                    arg.pgtypeinfoSize,
                    arg.flags);

            if (ret == 0) {
                System.out.println("fs-verity code signing enabled successfully.");
            } else {
                System.err.println("ioctl failed with error: " + ret);
                System.exit(1);
            }

            // Per-SO ioctl calls
            if (parsed.nativeLibCount > 0) {
                for (CodeSignBlockParser.NativeLibEntry entry : parsed.nativeLibEntries) {
                    System.out.println("Enabling code sign for: " + entry.fileName);
                    CodeSignEnableArg soArg = new CodeSignEnableArg();
                    soArg.hashAlgorithm = parsed.hashAlgorithm;
                    soArg.blockSize = 1 << parsed.logBlockSize;
                    soArg.sigSize = entry.sigSize;
                    soArg.signature = entry.signature;
                    soArg.dataSize = entry.dataSize;
                    soArg.treeOffset = 0;
                    soArg.rootHash = entry.rootHash;
                    soArg.pgtypeinfoOff = entry.soMapOffset;
                    soArg.pgtypeinfoSize = (int) entry.soMapSize;
                    soArg.flags = 1; // CSB_SIGN_INFO_MERKLE_TREE — root hash present

                    int soRet = FsVerityEnabler.enableCodeSign(
                            apkPath,
                            soArg.version,
                            soArg.csVersion,
                            soArg.hashAlgorithm,
                            soArg.blockSize,
                            soArg.salt != null ? soArg.salt : new byte[0],
                            soArg.signature,
                            soArg.dataSize,
                            soArg.treeOffset,
                            soArg.rootHash,
                            soArg.pgtypeinfoOff,
                            soArg.pgtypeinfoSize,
                            soArg.flags);

                    if (soRet == 0) {
                        System.out.println("  Enabled for " + entry.fileName);
                    } else {
                        System.err.println("  ioctl failed for " + entry.fileName
                                + " with error: " + soRet);
                        System.exit(1);
                    }
                }
            }
        }
    }

    private static String bytesToHex(byte[] bytes, int maxLen) {
        if (bytes == null) return "(null)";
        StringBuilder sb = new StringBuilder();
        int len = Math.min(bytes.length, maxLen);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        if (bytes.length > maxLen) sb.append("...");
        return sb.toString();
    }
}
