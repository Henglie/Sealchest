// JNI 桥：Kotlin NativeBridge ↔ C++ 实现。
// 函数名严格对应 com.henglie.sealchest.crypto.NativeBridge 的 external 声明。
//
// 自检（第一阶段）：一次已知 SHA-256 向量，证明 native 链路通。
// 卷操作（第二阶段）：openVolume / decryptUnits / closeVolume，转调 sc_volume.h
//   门面（其实现封在 veracrypt_core，本文件不碰任何 VeraCrypt 头）。

#include <jni.h>
#include <cstring>
#include <string>
#include "sha256.h"
#include "sc_volume.h"

using sc::Sha256;

namespace {

// 32 字节摘要 → 64 字符小写 hex
std::string toHex(const uint8_t digest[32]) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.resize(64);
    for (int i = 0; i < 32; ++i) {
        s[i * 2]     = d[(digest[i] >> 4) & 0xf];
        s[i * 2 + 1] = d[digest[i] & 0xf];
    }
    return s;
}

}  // namespace

extern "C" {

// 自检：SHA-256("abc") 应为
// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
JNIEXPORT jboolean JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeSelfTest(JNIEnv* /*env*/, jobject /*thiz*/) {
    const char* msg = "abc";
    uint8_t out[32];
    Sha256 ctx;
    ctx.update(reinterpret_cast<const uint8_t*>(msg), 3);
    ctx.final(out);
    static const char* expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    return toHex(out) == expected ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeVersion(JNIEnv* env, jobject /*thiz*/) {
    // 接入 VeraCrypt 核心后汇报实际算法集。
    return env->NewStringUTF(
        "sealchest-core 0.2 (VeraCrypt XTS: AES/Serpent/Twofish/Camellia/Kuznyechik; "
        "PRF: SHA256/SHA512/Whirlpool/BLAKE2s/Streebog/Argon2)");
}

// ---------------- 卷操作 ----------------
// 句柄以 jlong 往返 Kotlin，即 sc_volume* 的整数形。

// openVolume(header: ByteArray, password: ByteArray, pim: Int, prf: Int): Long
// 返回 0 表示开卷失败（密码错/格式不符/参数错）；非 0 为卷句柄。
JNIEXPORT jlong JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeOpenVolume(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray header, jbyteArray password, jint pim, jint prf) {

    if (header == nullptr || password == nullptr) return 0;
    if (env->GetArrayLength(header) < 512) return 0;

    const jsize pwLen = env->GetArrayLength(password);
    if (pwLen < 0 || pwLen > 128) return 0;

    jbyte* hdr = env->GetByteArrayElements(header, nullptr);
    jbyte* pw  = env->GetByteArrayElements(password, nullptr);
    if (hdr == nullptr || pw == nullptr) {
        if (hdr) env->ReleaseByteArrayElements(header, hdr, JNI_ABORT);
        if (pw)  env->ReleaseByteArrayElements(password, pw, JNI_ABORT);
        return 0;
    }

    int err = 0;
    sc_volume* v = sc_volume_open(
        reinterpret_cast<const uint8_t*>(hdr),
        reinterpret_cast<const uint8_t*>(pw), static_cast<int>(pwLen),
        static_cast<int>(pim), static_cast<int>(prf), &err);

    // 抹掉本地口令副本再释放（JNI_ABORT：不回写、丢弃）。
    std::memset(pw, 0, static_cast<size_t>(pwLen));
    env->ReleaseByteArrayElements(password, pw, JNI_ABORT);
    env->ReleaseByteArrayElements(header, hdr, JNI_ABORT);

    return reinterpret_cast<jlong>(v);
}

// decryptUnits(handle: Long, startUnit: Long, buf: ByteArray, nbrUnits: Int)
// 原地解密 buf 里的 nbrUnits 个 512B 数据单元。buf 长度须 ≥ nbrUnits*512。
JNIEXPORT void JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeDecryptUnits(
    JNIEnv* env, jobject /*thiz*/,
    jlong handle, jlong startUnit, jbyteArray buf, jint nbrUnits) {

    if (handle == 0 || buf == nullptr || nbrUnits <= 0) return;

    const jlong need = static_cast<jlong>(nbrUnits) * 512;
    if (env->GetArrayLength(buf) < need) return;

    jbyte* p = env->GetByteArrayElements(buf, nullptr);
    if (p == nullptr) return;

    sc_volume_decrypt_units(
        reinterpret_cast<sc_volume*>(handle),
        static_cast<uint64_t>(startUnit),
        reinterpret_cast<uint8_t*>(p),
        static_cast<uint32_t>(nbrUnits));

    // 0 = 回写解密结果到 Java 数组并释放。
    env->ReleaseByteArrayElements(buf, p, 0);
}

// encryptUnits(handle: Long, startUnit: Long, buf: ByteArray, nbrUnits: Int)
// 原地加密 buf 里的 nbrUnits 个 512B 数据单元（明文→密文）。buf 长度须 ≥ nbrUnits*512。
// 写入互通用：上层改好明文扇区后，加密回容器文件。与 nativeDecryptUnits 严格互逆。
JNIEXPORT void JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeEncryptUnits(
    JNIEnv* env, jobject /*thiz*/,
    jlong handle, jlong startUnit, jbyteArray buf, jint nbrUnits) {

    if (handle == 0 || buf == nullptr || nbrUnits <= 0) return;

    const jlong need = static_cast<jlong>(nbrUnits) * 512;
    if (env->GetArrayLength(buf) < need) return;

    jbyte* p = env->GetByteArrayElements(buf, nullptr);
    if (p == nullptr) return;

    sc_volume_encrypt_units(
        reinterpret_cast<sc_volume*>(handle),
        static_cast<uint64_t>(startUnit),
        reinterpret_cast<uint8_t*>(p),
        static_cast<uint32_t>(nbrUnits));

    // 0 = 回写加密结果到 Java 数组并释放。
    env->ReleaseByteArrayElements(buf, p, 0);
}

// closeVolume(handle: Long)：销毁密钥并释放句柄。
JNIEXPORT void JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeCloseVolume(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    if (handle != 0) sc_volume_close(reinterpret_cast<sc_volume*>(handle));
}

// --- 开卷后的只读信息 getter ---
JNIEXPORT jint JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeVolumeEa(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    return handle == 0 ? 0 : sc_volume_ea(reinterpret_cast<sc_volume*>(handle));
}

JNIEXPORT jint JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeVolumePrf(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    return handle == 0 ? 0 : sc_volume_prf(reinterpret_cast<sc_volume*>(handle));
}

JNIEXPORT jlong JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeVolumeSize(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    return handle == 0 ? 0
        : static_cast<jlong>(sc_volume_volume_size(reinterpret_cast<sc_volume*>(handle)));
}

JNIEXPORT jlong JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeEncryptedAreaStart(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    return handle == 0 ? 0
        : static_cast<jlong>(sc_volume_encrypted_area_start(reinterpret_cast<sc_volume*>(handle)));
}

JNIEXPORT jint JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeVolumeSectorSize(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    return handle == 0 ? 0
        : static_cast<jint>(sc_volume_sector_size(reinterpret_cast<sc_volume*>(handle)));
}

JNIEXPORT jboolean JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeVolumeIsHidden(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    return (handle != 0 && sc_volume_is_hidden(reinterpret_cast<sc_volume*>(handle)))
        ? JNI_TRUE : JNI_FALSE;
}

}  // extern "C"
