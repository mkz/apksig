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

#ifndef CODE_SIGN_ENABLE_ARG_H
#define CODE_SIGN_ENABLE_ARG_H

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * OpenHarmony kernel struct for FS_IOC_ENABLE_CODE_SIGN ioctl.
 * This struct is not part of standard Linux headers.
 */
struct code_sign_enable_arg {
    __u32 version;           /* struct version, must be 1 */
    __u32 cs_version;        /* code sign version: 2 = page info support */
    __u32 hash_algorithm;    /* 1 = SHA-256 */
    __u32 block_size;        /* 4096 */
    __u32 salt_size;
    __u32 sig_size;
    __u32 pgtypeinfo_size;
    __u64 salt_ptr;          /* userspace pointer to salt bytes */
    __u64 sig_ptr;           /* userspace pointer to PKCS#7 signature bytes */
    __u64 data_size;         /* data size covered by Merkle tree */
    __u64 tree_offset;       /* 0 = kernel computes tree */
    __u64 root_hash_ptr;     /* userspace pointer to 64-byte root hash */
    __u64 pgtypeinfo_off;    /* absolute offset of .pages.info data in file */
    __u32 flags;             /* bit0=merkle tree inlined, bits1+=unitSize */
};

#define FS_IOC_ENABLE_CODE_SIGN _IOW('f', 136, struct code_sign_enable_arg)

#endif /* CODE_SIGN_ENABLE_ARG_H */
