/* ============================================================
 *  密匣 Sealchest · VeraCrypt 卷操作纯净门面
 *
 *  对外只暴露开卷 / 解扇区 / 关卷三件事，且**不引入任何 VeraCrypt 头**。
 *  实现 sc_volume.c 编在 veracrypt_core 静态库里（force-include sc_compat.h），
 *  故 native_lib.cpp 只 include 本头即可，不必碰 Tcdefs.h/Crypto.h，
 *  也就绕开了「Endian.h 大小写自引用」与「LONG/WORD/TC_EVENT 缺类型」两坑。
 *
 *  设计：JNI 层保持"哑" —— 只做 XTS 数据单元的解密，单元号由上层（FAT 层）
 *  按数据区偏移算好传入。绝对偏移 → 单元号的映射语义留给上层与测试向量阶段确认。
 * ============================================================ */
#ifndef SC_VOLUME_H
#define SC_VOLUME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明卷句柄，内部即 PCRYPTO_INFO。 */
typedef struct sc_volume sc_volume;

/* PRF 选择：0 = 依次尝试全部 PRF（推荐，兼容任意容器）；
 * 非 0 对应 VeraCrypt PRF ID（SHA512=1/WHIRLPOOL=2/SHA256=3/BLAKE2S=4/STREEBOG=5/ARGON2=6）。 */

/* 开卷：header512 为卷起始 512 字节（含 salt）。成功返回句柄，失败返回 NULL；
 * 若 out_err 非空，写入 VeraCrypt ERR_* 码（0=成功，3=密码错，4=卷格式坏）。
 * password 为 UTF-8 字节，长度 password_len（≤128）。 */
sc_volume* sc_volume_open(const uint8_t* header512,
                          const uint8_t* password, int password_len,
                          int pim, int prf, int* out_err);

/* 原地解密 nbr_units 个 512 字节数据单元，起始 XTS 数据单元号 start_unit。
 * buf 长度须 = nbr_units * 512。 */
void sc_volume_decrypt_units(sc_volume* v, uint64_t start_unit,
                             uint8_t* buf, uint32_t nbr_units);

/* 原地加密 nbr_units 个 512 字节数据单元，起始 XTS 数据单元号 start_unit。
 * 与 sc_volume_decrypt_units 严格对称（同一密钥、同一 XTS 单元号语义）：
 * 明文 --encrypt--> 密文，写回容器后 VeraCrypt 桌面端能正常解开。
 * buf 长度须 = nbr_units * 512。写入互通的根基。 */
void sc_volume_encrypt_units(sc_volume* v, uint64_t start_unit,
                             uint8_t* buf, uint32_t nbr_units);

/* 关卷：销毁密钥并释放。传 NULL 安全无操作。 */
void sc_volume_close(sc_volume* v);

/* --- B2 创建容器 --- */

/* 灌熵：Kotlin SecureRandom（Android CSPRNG）经此注入 native 随机池。
 * 生成卷头前必须先灌足量（远超一次卷头所需），一次用尽即弃。
 * 池不足时 sc_volume_create_headers 会明确失败，绝不吐可预测随机。 */
void sc_random_seed(const uint8_t* entropy, int len);

/* 追加熵：手指滑动/涂抹采集的物理不可预测输入（坐标+时间戳），经此混入熵池
 * （对齐桌面 VC 晃鼠标收集熵；VC 走 RandaddBuf，本函数同一语义）。多次调用累积。
 * 与 sc_random_seed 互补：seed 灌 SecureRandom 基底，本函数叠加用户交互熵。 */
void sc_random_add_entropy(const uint8_t* buf, int len);

/* 抹除熵池（创建完成后调，不留主密钥种子于内存）。 */
void sc_random_wipe(void);

/* 池快照（仅供 UI 可视化，对齐桌面 VeraCrypt 显示 Random Pool）。
 * 只读拷贝当前池字节到 out（最多 len，out 应 ≥320 才能拿全池），绝不推进指针 / 消耗熵。
 * 返回实际拷贝字节数。 */
int sc_random_snapshot(uint8_t* out, int len);

/* 生成一对 VeraCrypt 卷头（主头 + 备份头，共享同一随机主密钥、各用独立随机盐）。
 * 调官方 CreateVolumeHeaderInMemory，字节级与桌面 VC 一致。
 *   out_primary / out_backup：各收 512B 有效头（调用方保证 ≥512B）。
 *   ea：加密算法 ID（AES=1…级联另计）；prf：PRF ID（不可为 0，须指定）；pim。
 *   password / password_len：keyfile 混入后的有效密码（UTF-8，可空长度 0）。
 *   volume_size：数据区字节数（不含头组）；encrypted_area_start：数据区起始（标准 131072）。
 * 成功返回 0（ERR_SUCCESS），失败返回 VeraCrypt ERR_* 码（熵不足 / 弱密钥 / 参数错）。 */
int sc_volume_create_headers(uint8_t* out_primary, uint8_t* out_backup,
                             int ea, int prf, int pim,
                             const uint8_t* password, int password_len,
                             uint64_t volume_size, uint64_t encrypted_area_start);

/* C2 生成一对隐藏卷头（隐藏主头 + 隐藏备份头，独立随机主密钥、各用独立随机盐）。
 * 字节级复刻 VC Format.c 隐藏卷分支：内部据 host_size/hidden_size 算保留区、
 * dataAreaSize、dataOffset，两头 hiddenVolumeSize=dataAreaSize（标记隐藏）、
 * encryptedAreaStart=dataOffset（数据区寄生在容器尾部）。
 *   out_primary / out_backup：各收 512B 有效头（调用方保证 ≥512B）。
 *   host_size：外层容器总字节数（含头组）；hidden_size：隐藏卷毛尺寸（含保留区）。
 * 头写盘位置由调用方负责：隐藏主头 → 偏移 65536；隐藏备份头 → host_size-65536。
 * 调用前须先 sc_random_seed 灌足熵。成功返回 0，尺寸非法返回 ERR_VOL_SIZE_WRONG。 */
int sc_volume_create_hidden_headers(uint8_t* out_primary, uint8_t* out_backup,
                                    int ea, int prf, int pim,
                                    const uint8_t* password, int password_len,
                                    uint64_t host_size, uint64_t hidden_size);

/* 改密码 / PIM / PRF（B1）：字节级复刻 VC ChangePwd（Common/Password.c:190）。
 * 主密钥不变，只用新密码 + 新盐重新派生 header key 重加密主头 + 备份头。
 *
 * 从已开卷句柄 v（其 v->ci 由 ReadVolumeHeaderWithAbort 填充）读取全部卷参数
 * 原样透传（ea/mode/master_keydata/VolumeSize/EncryptedAreaStart/EncryptedAreaLength/
 * RequiredProgramVersion/HeaderFlags/SectorSize），只 password/prf/pim 换新，
 * 内部各取新随机盐（故主头与备份头盐不同，与 VC 一致）。
 *   v：已成功开卷的句柄（不可为 NULL）。
 *   new_prf：新 PRF ID；传 0 = 保持原卷 PRF（对齐 ChangePwd 的 pkcs5==0 语义）。
 *   new_pim：新 PIM（<0 视作 0）。
 *   new_password / password_len：keyfile 混入后的新有效密码（UTF-8，可空长度 0）。
 *   out_primary / out_backup：各收 512B 重加密后的头（调用方保证 ≥512B）。
 * 成功返回 0（ERR_SUCCESS），失败返回 VeraCrypt ERR_* 码。
 * 调用前须先 sc_random_seed 灌足熵（内部取新盐用 RandgetBytes，池空返 FALSE 即失败）。 */
int sc_volume_rekey_headers(const sc_volume* v,
                            int new_prf, int new_pim,
                            const uint8_t* new_password, int password_len,
                            uint8_t* out_primary, uint8_t* out_backup);

/* --- X17 卷扩展（仅增大不缩小）---
 * 复用旧卷主密钥 + 原密码 + 原 PRF/PIM，只把 VolumeSize/EncryptedAreaLength
 * 改为 new_volume_size，调 CreateVolumeHeaderInMemory 重加密主头 + 备份头。
 *   v：已成功开卷的句柄（不可为 NULL）。
 *   new_volume_size：新数据区字节数（不含头组），须 > 当前 VolumeSize 且 512 对齐。
 *   password / password_len：keyfile 混入后的有效密码（UTF-8，可空长度 0）。
 *   out_primary / out_backup：各收 512B 重加密后的头（调用方保证 ≥512B）。
 * 成功返回 0（ERR_SUCCESS），失败返回 VeraCrypt ERR_* 码。
 * 调用前须先 sc_random_seed 灌足熵。 */
int sc_volume_expand_headers(const sc_volume* v,
                             uint64_t new_volume_size,
                             const uint8_t* password, int password_len,
                             uint8_t* out_primary, uint8_t* out_backup);


/* --- 只读信息 getter（开卷后卷头解析出的字段）--- */
int      sc_volume_ea(const sc_volume* v);            /* 加密算法 ID（AES=1…KUZNYECHIK=5，级联另计）*/
int      sc_volume_prf(const sc_volume* v);           /* 命中的 PRF ID */
uint64_t sc_volume_encrypted_area_start(const sc_volume* v);
uint64_t sc_volume_volume_size(const sc_volume* v);   /* 数据区字节数（不含头）*/
uint32_t sc_volume_sector_size(const sc_volume* v);
int      sc_volume_is_hidden(const sc_volume* v);

/* --- 数据区随机填充（复刻 VC FormatNoFs 临时密钥机制）---
 * 生成一套临时随机密钥（与 volume 真实主密钥无关），用 XTS 加密全零扇区填满
 * 数据区，使未用区在统计上与真实密文不可区分（隐藏卷可否认性地基）。
 * 用真实主密钥或明文随机字节都会破坏此性质。*/
typedef struct sc_fill sc_fill;

/* 打开填充器：ea = 加密算法 ID。内部取临时随机密钥 + 临时 k2 初始化 XTS。
 * 失败（RNG 池不足等）返回 NULL。*/
sc_fill* sc_volume_random_fill_open(int ea);

/* 填一块：buf 长度 = nbr_units*512，内部先清零再原地 XTS 加密写回。
 * start_unit = 该块首扇区的绝对数据单元号（文件绝对偏移/512）。*/
void sc_volume_random_fill_block(sc_fill* f, uint8_t* buf, uint64_t start_unit, uint32_t nbr_units);

/* 关闭并销毁临时密钥。*/
void sc_volume_random_fill_close(sc_fill* f);

#ifdef __cplusplus
}
#endif

#endif /* SC_VOLUME_H */
