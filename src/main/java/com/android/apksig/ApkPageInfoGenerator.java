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

package com.android.apksig;

import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.BitSet;
import java.util.List;

/**
 * Generates a page-type bitmap ({@code .pages.info}) for APKs, analogous to HAP's
 * {@code PageInfoGenerator}.
 *
 * <p>The bitmap annotates each 4 KiB page with 4 bits:
 * <ul>
 *   <li>bit 0 of unit: page belongs to an ELF executable ({@code PF_X}) segment</li>
 *   <li>bit 1 of unit: page belongs to a DEX bytecode file</li>
 *   <li>bits 2–3: unused (zero)</li>
 * </ul>
 *
 * <p>Coverage extends from file offset 0 up to (but not including) the data start of the
 * {@code .pages.info} entry itself ({@code maxEntryDataOffset}).
 */
class ApkPageInfoGenerator {

    static final String PAGES_INFO_ENTRY_NAME = ".pages.info";

    private static final int PAGE_SIZE = 4096;
    /** Number of bitmap bits allocated per 4 KiB page (the "unit size"). */
    private static final int BITS_PER_PAGE = 4;

    private static final byte CODE_ELF = 0; // bit index within page's 4-bit unit
    private static final byte CODE_DEX = 1; // bit index within page's 4-bit unit

    /** ELF magic bytes: 0x7F 'E' 'L' 'F' */
    private static final byte[] ELF_MAGIC = {0x7F, 0x45, 0x4C, 0x46};

    // ELF constants
    private static final byte ELF_CLASS_32 = 1;
    private static final byte ELF_CLASS_64 = 2;
    private static final byte ELF_DATA_LSB  = 1;
    private static final byte ELF_DATA_MSB  = 2;
    private static final int  ELF_HEADER_32_SIZE = 52;
    private static final int  ELF_HEADER_64_SIZE = 64;
    private static final int  ELF_PHDR_32_SIZE   = 32;
    private static final int  ELF_PHDR_64_SIZE   = 56;

    enum EntryType {
        NATIVE_LIB,
        DEX
    }

    /** Metadata about a runnable entry, with its simulated data offset in the output APK. */
    static class EntryInfo {
        final String name;
        final EntryType type;
        /** Absolute offset of the entry's data in the output APK (after alignment padding). */
        final long simulatedDataOffset;
        /** Uncompressed (= stored) data size in bytes. */
        final long dataSize;
        /** Original CD record, used to locate the entry in the input APK for ELF parsing. */
        final CentralDirectoryRecord cdRecord;

        EntryInfo(String name, EntryType type, long simulatedDataOffset, long dataSize,
                CentralDirectoryRecord cdRecord) {
            this.name = name;
            this.type = type;
            this.simulatedDataOffset = simulatedDataOffset;
            this.dataSize = dataSize;
            this.cdRecord = cdRecord;
        }
    }

    /**
     * Generates the {@code .pages.info} bitmap.
     *
     * @param entries             sorted list of NATIVE_LIB and DEX entries with simulated offsets
     * @param maxEntryDataOffset  absolute offset in the output APK where {@code .pages.info} data
     *                            starts; the bitmap covers pages [0, maxEntryDataOffset/4096)
     * @param inputApkLfhSection  input APK's LFH section, used to read .so bytes for ELF parsing
     * @return raw bitmap bytes, or an empty array if there are no entries to annotate
     */
    static byte[] generateBitMap(
            List<EntryInfo> entries,
            long maxEntryDataOffset,
            DataSource inputApkLfhSection) throws IOException {

        if (entries.isEmpty() || maxEntryDataOffset <= 0) {
            return new byte[0];
        }

        int numPages = (int) (maxEntryDataOffset / PAGE_SIZE);
        if (numPages == 0) {
            return new byte[0];
        }

        int numBits = numPages * BITS_PER_PAGE;
        BitSet bitmap = new BitSet(numBits);

        for (EntryInfo entry : entries) {
            if (entry.type == EntryType.DEX) {
                annotateDex(bitmap, entry, numPages);
            } else if (entry.type == EntryType.NATIVE_LIB) {
                annotateElf(bitmap, entry, numPages, inputApkLfhSection);
            }
        }

        // Convert BitSet to a little-endian byte array of exactly (numBits / 8) bytes.
        int byteLen = (numBits + 7) / 8;
        byte[] result = new byte[byteLen];
        long[] longs = bitmap.toLongArray();
        ByteBuffer buf = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN);
        for (long l : longs) {
            if (buf.remaining() >= 8) {
                buf.putLong(l);
            } else {
                // Write remaining bytes only
                for (int b = 0; b < buf.remaining(); b++) {
                    result[buf.position() + b] = (byte) ((l >>> (b * 8)) & 0xFF);
                }
                break;
            }
        }
        return result;
    }

    /** Annotates all pages covered by a DEX entry as DEX (bit 1). */
    private static void annotateDex(BitSet bitmap, EntryInfo entry, int numPages) {
        int startPage = (int) (entry.simulatedDataOffset / PAGE_SIZE);
        int endPage   = (int) ((entry.simulatedDataOffset + entry.dataSize + PAGE_SIZE - 1) / PAGE_SIZE);
        endPage = Math.min(endPage, numPages);
        for (int page = startPage; page < endPage; page++) {
            bitmap.set(page * BITS_PER_PAGE + CODE_DEX);
        }
    }

    /**
     * Annotates ELF executable-segment pages as ELF (bit 0).
     * Reads the .so content from the input APK LFH section, parses ELF program headers, and
     * annotates each page that falls within a {@code PF_X} segment.
     */
    private static void annotateElf(
            BitSet bitmap,
            EntryInfo entry,
            int numPages,
            DataSource inputApkLfhSection) throws IOException {
        try {
            LocalFileRecord lfr = LocalFileRecord.getRecord(
                    inputApkLfhSection, entry.cdRecord, inputApkLfhSection.size());
            long soDataStart = lfr.getStartOffsetInArchive() + lfr.getDataStartOffsetInRecord();
            long soDataSize  = entry.dataSize;

            if (soDataSize < ELF_HEADER_32_SIZE) return;

            // Read the ELF header (up to 64 bytes for 64-bit ELF).
            int headerReadSize = (int) Math.min(ELF_HEADER_64_SIZE, soDataSize);
            ByteBuffer header = inputApkLfhSection.getByteBuffer(soDataStart, headerReadSize);
            header.order(ByteOrder.LITTLE_ENDIAN);

            // Verify ELF magic.
            byte[] ident = new byte[16];
            header.get(ident);
            if (ident[0] != ELF_MAGIC[0] || ident[1] != ELF_MAGIC[1]
                    || ident[2] != ELF_MAGIC[2] || ident[3] != ELF_MAGIC[3]) {
                return;
            }

            byte eiClass = ident[4];
            byte eiData  = ident[5];
            if (eiData == ELF_DATA_MSB) {
                header.order(ByteOrder.BIG_ENDIAN);
            } else if (eiData != ELF_DATA_LSB) {
                return;
            }

            long ePhOff;
            int  ePhEntSize;
            int  ePhNum;

            if (eiClass == ELF_CLASS_32) {
                if (headerReadSize < ELF_HEADER_32_SIZE) return;
                // 32-bit ELF header layout (offsets from start of header):
                //  e_type(16), e_machine(18), e_version(20), e_entry(24), e_phoff(28),
                //  e_shoff(32), e_flags(36), e_ehsize(40), e_phentsize(42), e_phnum(44)
                ePhOff    = Integer.toUnsignedLong(header.getInt(28));
                ePhEntSize = Short.toUnsignedInt(header.getShort(42));
                ePhNum    = Short.toUnsignedInt(header.getShort(44));
            } else if (eiClass == ELF_CLASS_64) {
                // 64-bit ELF header layout:
                //  e_type(16), e_machine(18), e_version(20), e_entry(24), e_phoff(32),
                //  e_shoff(40), e_flags(48), e_ehsize(52), e_phentsize(54), e_phnum(56)
                ePhOff    = header.getLong(32);
                ePhEntSize = Short.toUnsignedInt(header.getShort(54));
                ePhNum    = Short.toUnsignedInt(header.getShort(56));
            } else {
                return;
            }

            if (ePhNum == 0 || ePhEntSize == 0) return;
            long phTableSize = (long) ePhNum * ePhEntSize;
            if (ePhOff + phTableSize > soDataSize) return;

            // Read program headers.
            ByteBuffer phBuf = inputApkLfhSection.getByteBuffer(
                    soDataStart + ePhOff, (int) phTableSize);
            phBuf.order(eiData == ELF_DATA_MSB ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

            for (int i = 0; i < ePhNum; i++) {
                phBuf.position(i * ePhEntSize);

                long pOffset;
                long pFilesz;
                int  pFlags;

                if (eiClass == ELF_CLASS_32) {
                    // 32-bit Phdr: p_type(0), p_offset(4), p_vaddr(8), p_paddr(12),
                    //              p_filesz(16), p_memsz(20), p_flags(24), p_align(28)
                    phBuf.getInt();    // p_type (skip)
                    pOffset = Integer.toUnsignedLong(phBuf.getInt());
                    phBuf.getInt();    // p_vaddr (skip)
                    phBuf.getInt();    // p_paddr (skip)
                    pFilesz = Integer.toUnsignedLong(phBuf.getInt());
                    phBuf.getInt();    // p_memsz (skip)
                    pFlags = phBuf.getInt();
                } else {
                    // 64-bit Phdr: p_type(0), p_flags(4), p_offset(8), p_vaddr(16),
                    //              p_paddr(24), p_filesz(32), p_memsz(40), p_align(48)
                    phBuf.getInt();    // p_type (skip)
                    pFlags = phBuf.getInt();
                    pOffset = phBuf.getLong();
                    phBuf.getLong();   // p_vaddr (skip)
                    phBuf.getLong();   // p_paddr (skip)
                    pFilesz = phBuf.getLong();
                }

                // Only annotate executable segments with non-zero file size.
                if ((pFlags & 1) == 0 || pFilesz == 0) continue;

                long segStart = entry.simulatedDataOffset + pOffset;
                long segEnd   = segStart + pFilesz;
                int startPage = (int) (segStart / PAGE_SIZE);
                int endPage   = (int) ((segEnd + PAGE_SIZE - 1) / PAGE_SIZE);
                endPage = Math.min(endPage, numPages);
                for (int page = startPage; page < endPage; page++) {
                    if (page >= 0) {
                        bitmap.set(page * BITS_PER_PAGE + CODE_ELF);
                    }
                }
            }
        } catch (ZipFormatException e) {
            // Unable to read the entry — skip ELF annotation silently.
        }
    }

    private ApkPageInfoGenerator() {}
}
