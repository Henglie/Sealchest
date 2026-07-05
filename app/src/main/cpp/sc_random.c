/* ============================================================
 *  密匣 Sealchest · 真随机注入（B2 创建容器用）
 *
 *  创建新容器需要密码学安全随机：卷头 salt（PKCS5_SALT_SIZE=64）+
 *  主密钥（EAGetKeySize*2，级联更多）。VeraCrypt 原生 RNG（Random.c /
 *  jitterentropy / RDRAND）未编入——它依赖 Windows 熵源与我们排除的汇编。
 *
 *  改由 Android 侧 SecureRandom 提供熵，经 JNI（sc_random_seed）灌入一个
 *  一次性熵池；VeraCrypt 内部的 RandgetBytes 从池顺序消费。
 *
 *  安全铁律（本文件存在的全部理由）：
 *    - 池耗尽时 RandgetBytes 返回 FALSE，令 CreateVolumeHeaderInMemory 以
 *      ERR_CIPHER_INIT_WEAK_KEY 失败，**绝不返回可预测数据**。
 *    - 旧 sc_stubs.c 里的 `memset(buf,0,len); return TRUE;` 是灾难性弱密钥源
 *      （全零盐 + 全零主密钥），已从 stub 删除，改由本文件正确实现。
 *    - 用完 sc_random_wipe 抹除池，不留主密钥种子在内存。
 * ============================================================ */

#include "Tcdefs.h"

#include <string.h>

/* 池容量：salt 64 + 主密钥最坏情形（三层级联 XTS，每层 EAGetKeySize*2）
 * 远小于此。4096 留足冗余，Kotlin 每次创建一次性灌满高质量 SecureRandom 熵。 */
#define SC_ENTROPY_POOL_SIZE 4096

static unsigned char sc_entropy_pool[SC_ENTROPY_POOL_SIZE];
static int sc_entropy_len = 0;   /* 本次灌入的可用熵字节数 */
static int sc_entropy_pos = 0;   /* 已消费位置（顺序消费，不回绕） */

/* Kotlin 经 JNI 灌入 SecureRandom 熵。覆盖式重置（每次创建前灌一次）。
 * len 超过池容量则截断到容量（正常用量几百字节，不会触发）。 */
void sc_random_seed(const unsigned char* entropy, int len)
{
    if (!entropy || len <= 0) {
        sc_entropy_len = 0;
        sc_entropy_pos = 0;
        return;
    }
    if (len > SC_ENTROPY_POOL_SIZE)
        len = SC_ENTROPY_POOL_SIZE;
    memcpy(sc_entropy_pool, entropy, (size_t) len);
    sc_entropy_len = len;
    sc_entropy_pos = 0;
}

/* 抹除熵池（创建完成后调，不留主密钥种子）。volatile 防优化掉。 */
void sc_random_wipe(void)
{
    volatile unsigned char* p = sc_entropy_pool;
    int i;
    for (i = 0; i < SC_ENTROPY_POOL_SIZE; i++)
        p[i] = 0;
    sc_entropy_len = 0;
    sc_entropy_pos = 0;
}

/* VeraCrypt 熵接口（替代 Random.c 的同名函数）。从注入池顺序消费 len 字节。
 * 池不足 → 返回 FALSE，绝不给可预测数据。hwnd / forceSlowPoll 忽略
 * （熵已由 SecureRandom 提供，无需慢速轮询）。 */
int RandgetBytes(void* hwnd, unsigned char* buf, int len, int forceSlowPoll)
{
    (void) hwnd;
    (void) forceSlowPoll;
    if (!buf || len < 0)
        return FALSE;
    if (sc_entropy_pos + len > sc_entropy_len)
        return FALSE;                       /* 熵不够，拒绝——不生成弱密钥 */
    memcpy(buf, sc_entropy_pool + sc_entropy_pos, (size_t) len);
    sc_entropy_pos += len;
    return TRUE;
}

/* CreateVolumeHeaderInMemory 只用 RandgetBytes；RandgetBytesFull 若被链接引用，
 * 走同一池（allowAnyLength 语义对我们无差别：要么给够，要么 FALSE）。 */
int RandgetBytesFull(void* hwnd, unsigned char* buf, int len, int forceSlowPoll, int allowAnyLength)
{
    (void) allowAnyLength;
    return RandgetBytes(hwnd, buf, len, forceSlowPoll);
}
