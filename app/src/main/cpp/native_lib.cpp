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

// --- B2 创建容器 ---

// seedRandom(entropy: ByteArray)：Kotlin SecureRandom 灌熵入 native 随机池。
// 生成卷头前必须先灌足量；池不足时 createHeaders 明确失败，绝不吐可预测随机。
JNIEXPORT void JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeSeedRandom(
    JNIEnv* env, jobject /*thiz*/, jbyteArray entropy) {
    if (entropy == nullptr) return;
    jsize len = env->GetArrayLength(entropy);
    if (len <= 0) return;
    jbyte* e = env->GetByteArrayElements(entropy, nullptr);
    if (e == nullptr) return;
    sc_random_seed(reinterpret_cast<const uint8_t*>(e), static_cast<int>(len));
    // 抹除 native 侧熵副本 + 回写清零到 Java 数组（调用方也应 fill(0)）。
    memset(e, 0, static_cast<size_t>(len));
    env->ReleaseByteArrayElements(entropy, e, 0);
}

// addEntropy(sample: ByteArray)：手指滑动采样（坐标+时间戳+压力）混入随机池。
// 对齐桌面 VC 晃鼠标收集熵：额外物理不可预测输入，经 sc_random_add_entropy 混入搅拌池。
JNIEXPORT void JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeAddEntropy(
    JNIEnv* env, jobject /*thiz*/, jbyteArray sample) {
    if (sample == nullptr) return;
    jsize len = env->GetArrayLength(sample);
    if (len <= 0) return;
    jbyte* s = env->GetByteArrayElements(sample, nullptr);
    if (s == nullptr) return;
    sc_random_add_entropy(reinterpret_cast<const uint8_t*>(s), static_cast<int>(len));
    env->ReleaseByteArrayElements(sample, s, JNI_ABORT);
}

// createHeaders(outPrimary, outBackup, ea, prf, pim, password, volumeSize, encStart): Int
// 生成主头 + 备份头（共享随机主密钥、各用独立随机盐），各写 512B 到 out 数组。
// 返回 0 = 成功，非 0 = VeraCrypt ERR_* 码。password 为 keyfile 混入后的有效密码。
JNIEXPORT jint JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeCreateHeaders(
    JNIEnv* env, jobject /*thiz*/,
    jbyteArray outPrimary, jbyteArray outBackup,
    jint ea, jint prf, jint pim, jbyteArray password,
    jlong volumeSize, jlong encStart) {

    if (outPrimary == nullptr || outBackup == nullptr || password == nullptr) return -1;
    if (env->GetArrayLength(outPrimary) < 512 || env->GetArrayLength(outBackup) < 512) return -1;

    jsize plen = env->GetArrayLength(password);
    jbyte* pbuf = env->GetByteArrayElements(password, nullptr);
    jbyte* prim = env->GetByteArrayElements(outPrimary, nullptr);
    jbyte* back = env->GetByteArrayElements(outBackup, nullptr);
    if (pbuf == nullptr || prim == nullptr || back == nullptr) {
        if (pbuf) env->ReleaseByteArrayElements(password, pbuf, JNI_ABORT);
        if (prim) env->ReleaseByteArrayElements(outPrimary, prim, JNI_ABORT);
        if (back) env->ReleaseByteArrayElements(outBackup, back, JNI_ABORT);
        return -1;
    }

    int err = sc_volume_create_headers(
        reinterpret_cast<uint8_t*>(prim), reinterpret_cast<uint8_t*>(back),
        static_cast<int>(ea), static_cast<int>(prf), static_cast<int>(pim),
        reinterpret_cast<const uint8_t*>(pbuf), static_cast<int>(plen),
        static_cast<uint64_t>(volumeSize), static_cast<uint64_t>(encStart));

    // 抹除口令 native 副本（JNI_ABORT 不回写 Java 数组，仅清 native 侧）。
    memset(pbuf, 0, static_cast<size_t>(plen));
    env->ReleaseByteArrayElements(password, pbuf, JNI_ABORT);
    // 成功才回写头（0=回写），失败 ABORT 不留半成品。
    env->ReleaseByteArrayElements(outPrimary, prim, err == 0 ? 0 : JNI_ABORT);
    env->ReleaseByteArrayElements(outBackup, back, err == 0 ? 0 : JNI_ABORT);
    return static_cast<jint>(err);
}

// rekeyHeaders(handle, newPrf, newPim, newPassword, outPrimary, outBackup): Int
// B1 改密码/PIM/PRF：复用已开卷句柄的旧主密钥，用新口令重加密主头+备份头，各写 512B 到 out。
// 返回 0=成功，非 0=VeraCrypt ERR_*。newPassword 为 keyfile 混入后的有效密码。
// 调用前须先 nativeSeedRandom 灌足熵（内部取新盐用 RandgetBytes）。
JNIEXPORT jint JNICALL
Java_com_henglie_sealchest_crypto_NativeBridge_nativeRekeyHeaders(
    JNIEnv* env, jobject /*thiz*/,
    jlong handle, jint newPrf, jint newPim, jbyteArray newPassword,
    jbyteArray outPrimary, jbyteArray outBackup) {

    if (handle == 0 || newPassword == nullptr || outPrimary == nullptr || outBackup == nullptr) return -1;
    if (env->GetArrayLength(outPrimary) < 512 || env->GetArrayLength(outBackup) < 512) return -1;

    jsize plen = env->GetArrayLength(newPassword);
    jbyte* pbuf = env->GetByteArrayElements(newPassword, nullptr);
    jbyte* prim = env->GetByteArrayElements(outPrimary, nullptr);
    jbyte* back = env->GetByteArrayElements(outBackup, nullptr);
    if (pbuf == nullptr || prim == nullptr || back == nullptr) {
        if (pbuf) env->ReleaseByteArrayElements(newPassword, pbuf, JNI_ABORT);
        if (prim) env->ReleaseByteArrayElements(outPrimary, prim, JNI_ABORT);
        if (back) env->ReleaseByteArrayElements(outBackup, back, JNI_ABORT);
        return -1;
    }

    int err = sc_volume_rekey_headers(
        reinterpret_cast<sc_volume*>(handle),
        static_cast<int>(newPrf), static_cast<int>(newPim),
        reinterpret_cast<const uint8_t*>(pbuf), static_cast<int>(plen),
        reinterpret_cast<uint8_t*>(prim), reinterpret_cast<uint8_t*>(back));

    memset(pbuf, 0, static_cast<size_t>(plen));
    env->ReleaseByteArrayElements(newPassword, pbuf, JNI_ABORT);
    env->ReleaseByteArrayElements(outPrimary, prim, err == 0 ? 0 : JNI_ABORT);
    env->ReleaseByteArrayElements(outBackup, back, err == 0 ? 0 : JNI_ABORT);
    return static_cast<jint>(err);
}

}  // extern "C"
