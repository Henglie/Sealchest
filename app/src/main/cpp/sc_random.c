/* ============================================================
 *  密匣 Sealchest · 熵池与真随机（B2 创建容器用）
 *
 *  ── 为什么存在 ──
 *  创建新容器需要密码学安全随机：卷头 salt（PKCS5_SALT_SIZE=64）+ 随机主密钥
 *  （EAGetKeySize*2，级联更多）。VeraCrypt 原生 Random.c 深度耦合 Windows
 *  （鼠标钩子 / 后台轮询线程 / CryptoAPI / CriticalSection），移植整文件要 stub
 *  十几个 Windows 符号，且每次上游更新都得重新核对 —— 维护地狱。故不编入 Random.c。
 *
 *  ── 做法（与 KeyfileMixer 同一原则：复刻“格式/算法”，不引入平台桩）──
 *  本文件字节级复刻 VeraCrypt RNG 池的**搅拌与取数算法**（Random.c 的 RandaddByte /
 *  Randmix / RandgetBytesFull），只把它依赖的 Windows 熵源换成：
 *    ① Android SecureRandom（/dev/urandom CSPRNG，底层内核熵池）——主熵源，
 *       经 JNI sc_random_seed 灌入；
 *    ② 用户手指在屏幕滑动采集的（坐标 + 时间戳 + 压力）——对齐桌面 VeraCrypt
 *       “晃鼠标收集熵”的物理不可预测输入，经 JNI sc_random_add_entropy 混入。
 *  搅拌用的 SHA-512（DEFAULT_HASH_ALGORITHM = FIRST_PRF_ID = SHA512）已编入。
 *  依赖面 = 仅已编入的 sha512_*，零 Windows 桩，上游更新零负担。
 *
 *  ── 与桌面 VeraCrypt 的对齐点（可审计）──
 *    · 池大小 RNG_POOL_SIZE = 320（Random.h）。
 *    · RandaddByte：pool[i] += x（模加，非覆盖）；每 RANDMIX_BYTE_INTERVAL=16 字节 Randmix。
 *    · Randmix：分块（每块 SHA512_DIGESTSIZE=64），对整池哈希，摘要 XOR 回该块。320/64=5 块。
 *    · 手指熵先经 CRC32 扩散再入池，同 Random.c MouseProc 的做法（CRC32 仅扩散，
 *      随后由 Randmix 的密码学哈希处理）。
 *    · RandgetBytes：拷字节 → 反转整池(~) → Randmix → 用新池 XOR 输出（前向保密，
 *      防从输出反推池后续状态）→ 读指针环绕。对齐 RandgetBytesFull。
 *
 *  ── 安全铁律 ──
 *    · 池未经 SecureRandom 灌种（sc_random_seed 未成功调用）→ RandgetBytes 返回 FALSE，
 *      令 CreateVolumeHeaderInMemory 以 ERR_CIPHER_INIT_WEAK_KEY 失败，绝不吐可预测数据。
 *    · 旧 sc_stubs.c 的 `memset(buf,0,len); return TRUE;` 是灾难性弱密钥源（全零盐 +
 *      全零主密钥），已删除，由本文件取代。
 *    · sc_random_wipe 抹除全部池状态，不留主密钥种子在内存。
 * ============================================================ */

#include "Tcdefs.h"
#include "Crypto.h"          /* SHA512 / hash ctx（Sha2.h 经此可达） */
#include "Crypto/Sha2.h"

#include <string.h>
#include <pthread.h>

/* 与 VeraCrypt Random.h 对齐（勿改，改了即偏离原版搅拌语义）。 */
#define SC_RNG_POOL_SIZE        320
#define SC_RANDMIX_BYTE_INTERVAL 16
#define SC_SHA512_DIGEST        64      /* SHA512_DIGESTSIZE；320 % 64 == 0（5 块）*/

/* 320 主熵池 + 读写指针，全套受一把锁保护（JNI 可能从 UI 线程灌熵、IO 线程取数）。 */
static pthread_mutex_t sc_rand_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned char   sc_rand_pool[SC_RNG_POOL_SIZE];
static int             sc_rand_write_idx = 0;   /* nRandIndex：混入写指针 */
static int             sc_rand_read_idx  = 0;   /* randPoolReadIndex：取数读指针 */
static int             sc_rand_seeded    = 0;   /* 是否已由 SecureRandom 灌过种 */

/* 标准 CRC32 表（多项式 0xEDB88320），与 KeyfileMixer / VeraCrypt Crc.c 一致。
 * 仅用于把输入字节“扩散”后再入池（对齐 MouseProc），非安全组件。 */
static unsigned int sc_crc32_tab[256];
static int sc_crc32_ready = 0;

static void sc_crc32_init(void)
{
    if (sc_crc32_ready) return;
    for (unsigned int n = 0; n < 256; n++) {
        unsigned int c = n;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        sc_crc32_tab[n] = c;
    }
    sc_crc32_ready = 1;
}

/* 池混合函数（复刻 Randmix）：分块，对整池 SHA512，摘要 XOR 回该块位置。
 * 调用方须持锁。 */
static void sc_randmix(void)
{
    unsigned char digest[SC_SHA512_DIGEST];
    int poolIndex, di;
    for (poolIndex = 0; poolIndex < SC_RNG_POOL_SIZE; poolIndex += SC_SHA512_DIGEST) {
        sha512_ctx ctx;
        sha512_begin(&ctx);
        sha512_hash(sc_rand_pool, SC_RNG_POOL_SIZE, &ctx);
        sha512_end(digest, &ctx);
        for (di = 0; di < SC_SHA512_DIGEST; di++)
            sc_rand_pool[poolIndex + di] ^= digest[di];
        burn(&ctx, sizeof(ctx));
    }
    burn(digest, sizeof(digest));
}

/* 单字节入池（复刻 RandaddByte 宏）：环绕判断 → 模加 → 每 16 字节触发 Randmix。
 * 调用方须持锁。 */
static void sc_rand_add_byte(unsigned char x)
{
    if (sc_rand_write_idx == SC_RNG_POOL_SIZE) sc_rand_write_idx = 0;
    sc_rand_pool[sc_rand_write_idx] = (unsigned char)(sc_rand_pool[sc_rand_write_idx] + x);
    if (sc_rand_write_idx % SC_RANDMIX_BYTE_INTERVAL == 0) sc_randmix();
    sc_rand_write_idx++;
}

/* 缓冲入池：先 CRC32 扩散（对齐 MouseProc 的 UPDC32 预处理），再逐字节入池。
 * 调用方须持锁。 */
static void sc_rand_add_buf_locked(const unsigned char* buf, int len)
{
    unsigned int crc = 0xFFFFFFFFu;
    int i;
    sc_crc32_init();
    for (i = 0; i < len; i++) {
        crc = sc_crc32_tab[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
        /* 原字节 + CRC 滚动值都入池：原字节保熵，CRC 促扩散。 */
        sc_rand_add_byte(buf[i]);
        sc_rand_add_byte((unsigned char)(crc));
        sc_rand_add_byte((unsigned char)(crc >> 8));
        sc_rand_add_byte((unsigned char)(crc >> 16));
        sc_rand_add_byte((unsigned char)(crc >> 24));
    }
}

/* ── JNI 入口 ── */

/* 主熵灌种：Android SecureRandom 的字节。混入池后标记 seeded，并 Randmix 一次收口。
 * 每次创建容器前调（Kotlin 保证给足量高质量熵）。可多次调用累加。 */
void sc_random_seed(const unsigned char* entropy, int len)
{
    if (!entropy || len <= 0) return;
    pthread_mutex_lock(&sc_rand_lock);
    sc_rand_add_buf_locked(entropy, len);
    sc_randmix();
    sc_rand_seeded = 1;
    pthread_mutex_unlock(&sc_rand_lock);
}

/* 用户交互熵：手指滑动采集的坐标/时间戳/压力等原始字节。混入池增强不可预测性，
 * 对齐桌面 VeraCrypt 晃鼠标。不单独置 seeded —— 交互熵是增强，主熵仍须 SecureRandom。 */
void sc_random_add_entropy(const unsigned char* buf, int len)
{
    if (!buf || len <= 0) return;
    pthread_mutex_lock(&sc_rand_lock);
    sc_rand_add_buf_locked(buf, len);
    pthread_mutex_unlock(&sc_rand_lock);
}

/* 抹除全部池状态（创建完成后调）。volatile 防被优化掉。 */
void sc_random_wipe(void)
{
    volatile unsigned char* p = sc_rand_pool;
    int i;
    pthread_mutex_lock(&sc_rand_lock);
    for (i = 0; i < SC_RNG_POOL_SIZE; i++) p[i] = 0;
    sc_rand_write_idx = 0;
    sc_rand_read_idx = 0;
    sc_rand_seeded = 0;
    pthread_mutex_unlock(&sc_rand_lock);
}

/* VeraCrypt 熵接口（取代 Random.c 同名符号）。复刻 RandgetBytesFull 取数 + 前向保密：
 * 拷字节 → 反转整池(~) → Randmix → 用新池 XOR 输出 → 读指针环绕。
 * 未灌种则返回 FALSE（绝不吐可预测数据）。hwnd/forceSlowPoll 忽略。 */
int RandgetBytes(void* hwnd, unsigned char* buf, int len, int forceSlowPoll)
{
    int i, remaining, looplen;
    int ret = TRUE;
    (void)hwnd; (void)forceSlowPoll;

    if (!buf || len < 0) return FALSE;

    pthread_mutex_lock(&sc_rand_lock);

    /* 安全闸：没经 SecureRandom 灌种绝不出数 —— 宁可创建失败，不出弱密钥。 */
    if (!sc_rand_seeded) {
        pthread_mutex_unlock(&sc_rand_lock);
        return FALSE;
    }

    remaining = len;
    while (remaining > 0) {
        looplen = (remaining > SC_RNG_POOL_SIZE) ? SC_RNG_POOL_SIZE : remaining;

        /* 从池拷到输出。 */
        for (i = 0; i < looplen; i++) {
            buf[i] = sc_rand_pool[sc_rand_read_idx++];
            if (sc_rand_read_idx == SC_RNG_POOL_SIZE) sc_rand_read_idx = 0;
        }

        /* 反转整池（每 u32 取反），对齐 RandgetBytesFull 的 pool inversion。 */
        {
            unsigned int* p32 = (unsigned int*) sc_rand_pool;
            int n32 = SC_RNG_POOL_SIZE / 4;
            for (i = 0; i < n32; i++) p32[i] = ~p32[i];
        }

        /* 再搅拌（原版此处 FastPoll 混入系统熵，我们无 Windows 熵源，改 Randmix 搅拌）。 */
        sc_randmix();

        /* 用搅拌后的池 XOR 输出，防池状态经输出泄漏（前向保密）。 */
        for (i = 0; i < looplen; i++) {
            buf[i] ^= sc_rand_pool[sc_rand_read_idx++];
            if (sc_rand_read_idx == SC_RNG_POOL_SIZE) sc_rand_read_idx = 0;
        }

        buf += looplen;
        remaining -= looplen;
    }

    pthread_mutex_unlock(&sc_rand_lock);
    return ret;
}

int RandgetBytesFull(void* hwnd, unsigned char* buf, int len, int forceSlowPoll, int allowAnyLength)
{
    (void)allowAnyLength;
    return RandgetBytes(hwnd, buf, len, forceSlowPoll);
}

/* 池快照（仅供 UI 可视化，对齐桌面 VeraCrypt 显示 Random Pool）。
 * 纯拷贝当前池的原始字节到 out，最多 len 字节（out 应 ≥ SC_RNG_POOL_SIZE 才能拿全池）。
 * 绝不推进读/写指针、绝不搅拌、绝不消耗熵——展示是只读旁观，不能影响真实取数。
 * 返回实际拷贝字节数。未灌种也可看（池此时是交互熵累积的中间态）。 */
int sc_random_snapshot(unsigned char* out, int len)
{
    int n, i;
    if (!out || len <= 0) return 0;
    n = (len < SC_RNG_POOL_SIZE) ? len : SC_RNG_POOL_SIZE;
    pthread_mutex_lock(&sc_rand_lock);
    for (i = 0; i < n; i++) out[i] = sc_rand_pool[i];
    pthread_mutex_unlock(&sc_rand_lock);
    return n;
}
