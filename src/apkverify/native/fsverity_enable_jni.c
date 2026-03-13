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

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#include "code_sign_enable_arg.h"

/*
 * JNI implementation for FsVerityEnabler.enableCodeSign().
 *
 * Receives all fields as primitives/byte arrays, pins the arrays, populates the
 * kernel struct, and calls ioctl(fd, FS_IOC_ENABLE_CODE_SIGN, &arg).
 *
 * Returns 0 on success, -errno on failure.
 */
JNIEXPORT jint JNICALL
Java_com_android_apkverify_FsVerityEnabler_enableCodeSign(
        JNIEnv *env,
        jclass clazz,
        jstring path,
        jint version,
        jint csVersion,
        jint hashAlgorithm,
        jint blockSize,
        jbyteArray salt,
        jbyteArray signature,
        jlong dataSize,
        jlong treeOffset,
        jbyteArray rootHash,
        jlong pgtypeinfoOff,
        jint pgtypeinfoSize,
        jint flags) {

    const char *pathStr = (*env)->GetStringUTFChars(env, path, NULL);
    if (!pathStr) {
        return -ENOMEM;
    }

    int fd = open(pathStr, O_RDONLY);
    (*env)->ReleaseStringUTFChars(env, path, pathStr);
    if (fd < 0) {
        return -errno;
    }

    jbyte *saltPtr = NULL;
    jbyte *sigPtr = NULL;
    jbyte *hashPtr = NULL;
    jint saltLen = 0;
    jint sigLen = 0;

    if (salt) {
        saltLen = (*env)->GetArrayLength(env, salt);
        saltPtr = (*env)->GetByteArrayElements(env, salt, NULL);
    }
    if (signature) {
        sigLen = (*env)->GetArrayLength(env, signature);
        sigPtr = (*env)->GetByteArrayElements(env, signature, NULL);
    }
    if (rootHash) {
        hashPtr = (*env)->GetByteArrayElements(env, rootHash, NULL);
    }

    struct code_sign_enable_arg arg;
    memset(&arg, 0, sizeof(arg));
    arg.version = (uint32_t) version;
    arg.cs_version = (uint32_t) csVersion;
    arg.hash_algorithm = (uint32_t) hashAlgorithm;
    arg.block_size = (uint32_t) blockSize;
    arg.salt_size = (uint32_t) saltLen;
    arg.sig_size = (uint32_t) sigLen;
    arg.pgtypeinfo_size = (uint32_t) pgtypeinfoSize;
    arg.salt_ptr = (uint64_t)(uintptr_t) saltPtr;
    arg.sig_ptr = (uint64_t)(uintptr_t) sigPtr;
    arg.data_size = (uint64_t) dataSize;
    arg.tree_offset = (uint64_t) treeOffset;
    arg.root_hash_ptr = (uint64_t)(uintptr_t) hashPtr;
    arg.pgtypeinfo_off = (uint64_t) pgtypeinfoOff;
    arg.flags = (uint32_t) flags;

    int ret = ioctl(fd, FS_IOC_ENABLE_CODE_SIGN, &arg);
    int saved_errno = errno;

    if (saltPtr) (*env)->ReleaseByteArrayElements(env, salt, saltPtr, JNI_ABORT);
    if (sigPtr) (*env)->ReleaseByteArrayElements(env, signature, sigPtr, JNI_ABORT);
    if (hashPtr) (*env)->ReleaseByteArrayElements(env, rootHash, hashPtr, JNI_ABORT);

    close(fd);

    return (ret == 0) ? 0 : -saved_errno;
}
