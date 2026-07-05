/* ============================================================
 *  密匣 Sealchest · VeraCrypt 平台符号桩
 *
 *  VeraCrypt 非 boot 代码引用、但被排除文件（EncryptionThreadPool.c /
 *  Random.c / Aes_hw_*）本该提供的符号，在此集中桩实现。桩分两类：
 *    A. 死代码符号：写卷 / 多线程派生路径引用，只读开卷永不执行 —— 桩到
 *       能链接即可，行为不求真。
 *    B. 单线程执行路径符号：GetEncryptionThreadCount 返 1、DoWork 直调
 *       *DataUnitsCurrentThread —— 必须行为正确。
 *
 *  force-include sc_compat.h 已生效，LONG/WORD/TC_EVENT 等类型可用。
 * ============================================================ */
#include "Tcdefs.h"
#include "Crypto.h"
#include "Common/Endian.h"

/* EncryptionThreadPoolWorkType 定义在 EncryptionThreadPool.h，该头还声明一堆
 * 用 TC_EVENT/LONG 的函数。sc_compat.h 已补类型，可安全 include。 */
#include "EncryptionThreadPool.h"

/* ---- B. 单线程加解密派发（行为必须正确）------------------------
 * Crypto.c 的 EncryptDataUnits/DecryptDataUnits 无条件调 DoWork，
 * 原多线程实现在 EncryptionThreadPool.c（已排除）。这里按 work type
 * 直调对应 CurrentThread 版，等价单线程执行。 */
extern void EncryptDataUnitsCurrentThread (uint8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);
extern void DecryptDataUnitsCurrentThread (uint8 *buf, const UINT64_STRUCT *structUnitNo, TC_LARGEST_COMPILER_UINT nbrUnits, PCRYPTO_INFO ci);

void EncryptionThreadPoolDoWork (EncryptionThreadPoolWorkType type, uint8 *data,
                                 const UINT64_STRUCT *startUnitNo, uint32 unitCount,
                                 PCRYPTO_INFO cryptoInfo)
{
    switch (type)
    {
    case EncryptDataUnitsWork:
        EncryptDataUnitsCurrentThread (data, startUnitNo, unitCount, cryptoInfo);
        break;
    case DecryptDataUnitsWork:
        DecryptDataUnitsCurrentThread (data, startUnitNo, unitCount, cryptoInfo);
        break;
    default:
        /* DeriveKeyWork / ReadVolumeHeaderFinalizationWork 只在线程池模式下
         * 由 BeginKeyDerivation 派发；单线程路径 (encryptionThreadCount==1)
         * 不会走到，空实现即可。 */
        break;
    }
}

/* GetEncryptionThreadCount 返 1 — 这是让 Volumes.c ReadVolumeHeader 跳过
 * 整个线程池分支、直接走单线程 derive_key_* 的总开关。 */
size_t GetEncryptionThreadCount (void) { return 1; }
size_t GetMaxEncryptionThreadCount (void) { return 1; }
size_t GetCpuCount (WORD* pGroupCount) { if (pGroupCount) *pGroupCount = 1; return 1; }
BOOL   IsEncryptionThreadPoolRunning (void) { return FALSE; }

/* 线程池生命周期管理：单线程无池，空桩。 */
BOOL EncryptionThreadPoolStart (size_t encryptionFreeCpuCount) { (void)encryptionFreeCpuCount; return TRUE; }
void EncryptionThreadPoolStop (void) { }

/* BeginKeyDerivation / BeginReadVolumeHeaderFinalization：仅线程池模式
 * (encryptionThreadCount>1) 调用，单线程路径为死代码。桩到能链接。 */
void EncryptionThreadPoolBeginKeyDerivation (TC_EVENT *completionEvent, TC_EVENT *noOutstandingWorkItemEvent,
                                             LONG *completionFlag, LONG *outstandingWorkItemCount,
                                             int pkcs5Prf, unsigned char *password, int passwordLength,
                                             unsigned char *salt, int iterationCount, int memoryCost,
                                             unsigned char *derivedKey, LONG *derivationResult,
                                             LONG volatile *pAbortKeyDerivation)
{
    (void)completionEvent; (void)noOutstandingWorkItemEvent; (void)completionFlag;
    (void)outstandingWorkItemCount; (void)pkcs5Prf; (void)password; (void)passwordLength;
    (void)salt; (void)iterationCount; (void)memoryCost; (void)derivedKey;
    (void)derivationResult; (void)pAbortKeyDerivation;
}

void EncryptionThreadPoolBeginReadVolumeHeaderFinalization (TC_EVENT *keyDerivationCompletedEvent, TC_EVENT *noOutstandingWorkItemEvent,
                                                            LONG* outstandingWorkItemCount, void* keyInfoBuffer, int keyInfoBufferSize,
                                                            void* keyDerivationWorkItems, int keyDerivationWorkItemsSize)
{
    (void)keyDerivationCompletedEvent; (void)noOutstandingWorkItemEvent; (void)outstandingWorkItemCount;
    (void)keyInfoBuffer; (void)keyInfoBufferSize; (void)keyDerivationWorkItems; (void)keyDerivationWorkItemsSize;
}

/* ---- A. AES 硬件加速桩（死代码，恒不执行）--------------------------
 * sc_compat.h 关了 AES-NI/ARM-AES，IsAesHwCpuSupported() 恒 FALSE，
 * Crypto.c 里所有 aes_hw_cpu_* 调用都在 if(IsAesHwCpuSupported()) 内，
 * 永不进入。桩到能链接即可，真进来了 abort 暴露 bug。 */
#include <stdlib.h>
void aes_hw_cpu_encrypt (const uint8 *ks, uint8 *data) { (void)ks; (void)data; abort(); }
void aes_hw_cpu_decrypt (const uint8 *ks, uint8 *data) { (void)ks; (void)data; abort(); }
void aes_hw_cpu_encrypt_32_blocks (const uint8 *ks, uint8 *data) { (void)ks; (void)data; abort(); }
void aes_hw_cpu_decrypt_32_blocks (const uint8 *ks, uint8 *data) { (void)ks; (void)data; abort(); }

/* --- Serpent 单块无需包装 ------------------------------------------
 * 原以为 Crypto.c 的单块 serpent_encrypt/decrypt 需在此包装 blocks=1，
 * 实测 SerpentFast.h 已把这俩定义成宏（直接展开为 _blocks(...,1,...)），
 * 故不需要任何桩。编 SerpentFast.c（出 _blocks + set_key），不编
 * Serpent.c，避免 serpent_set_key 重复定义。 */

/* --- RNG：已移交 sc_random.c（B2 起）------------------------------
 * RandgetBytes / RandgetBytesFull 原在此桩返 FALSE（只读路径安全占位）。
 * B2 创建容器需真随机 → 移到 sc_random.c，由 Kotlin SecureRandom 经 JNI
 * 注入熵池后按需吐出。此处删桩，避免与 sc_random.c 同名符号重复定义。
 * 安全不变量：熵池未灌够时 sc_random.c 的实现返 FALSE，绝不吐弱/零随机。 */

/* --- A. t1ha 桩（RAM 加密路径死代码）------------------------------
 * Crypto.c 的 GetEncryptionID / VcProtectKeys 用 t1ha 做 RAM 加密密钥
 * 混淆，只读开卷完全不涉及。t1ha 的 .c（t1ha2.c/t1ha_selfcheck.c）未编入，
 * 这两个符号由此桩满足链接。selfcheck 返非 0（"失败"），保证真误入也不
 * 走 t1ha 分支。 */
#include <stdint.h>
int t1ha_selfcheck__t1ha2 (void) { return 1; }
uint64_t t1ha2_atonce128 (uint64_t *extra_result, const void *data, size_t length, uint64_t seed)
{
    (void)data; (void)length; (void)seed;
    if (extra_result) *extra_result = 0;
    return 0;
}

/* --- A. ChaCha RNG / ChaCha256 桩（RAM 加密路径死代码）--------------
 * Crypto.c 的 RAM 加密（VcProtectKeys/GetEncryptionID 一系）用 ChaCha
 * 做密钥流；chacha256.c/chachaRng.c 未编入。只读开卷不做 RAM 加密，
 * 这几个符号仅为满足链接。真误入会安全无操作（不吐随机流）。
 * include 真头保证结构体/签名与 Crypto.c 处一致。 */
#include "chacha256.h"
#include "chachaRng.h"

void ChaCha256Init (ChaCha256Ctx* ctx, const unsigned char* key, const unsigned char* iv, int rounds)
{ (void)ctx; (void)key; (void)iv; (void)rounds; }
void ChaCha256Encrypt (ChaCha256Ctx* ctx, const unsigned char* in, size_t len, unsigned char* out)
{ (void)ctx; if (in && out && in != out) memcpy(out, in, len); }

void ChaCha20RngInit (ChaCha20RngCtx* pCtx, const unsigned char* key, GetRandSeedFn rngCallback, size_t skip)
{ (void)pCtx; (void)key; (void)rngCallback; (void)skip; }
void ChaCha20RngGetBytes (ChaCha20RngCtx* pCtx, unsigned char* buffer, size_t bufferLen)
{ (void)pCtx; if (buffer) memset(buffer, 0, bufferLen); }

/* --- xts_encrypt/decrypt 无需桩（WOLFCRYPT_BACKEND 才引用）----------
 * 曾误加这俩桩。实测 Xts.c 的 EncryptBufferXTS/DecryptBufferXTS 只在
 * #ifdef WOLFCRYPT_BACKEND 的 #else 分支调 xts_encrypt/decrypt；我们没定义
 * WOLFCRYPT_BACKEND，走 #ifndef 的 EncryptBufferXTSParallel/NonParallel
 * 纯软路径，xts_encrypt/decrypt 符号从不被引用 → 无需桩。且 word64 仅
 * WOLFCRYPT_BACKEND 下由 wolfssl 提供，桩它反而引 unknown type 'word64'。 */
