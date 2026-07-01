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

/* 关卷：销毁密钥并释放。传 NULL 安全无操作。 */
void sc_volume_close(sc_volume* v);

/* --- 只读信息 getter（开卷后卷头解析出的字段）--- */
int      sc_volume_ea(const sc_volume* v);            /* 加密算法 ID（AES=1…KUZNYECHIK=5，级联另计）*/
int      sc_volume_prf(const sc_volume* v);           /* 命中的 PRF ID */
uint64_t sc_volume_encrypted_area_start(const sc_volume* v);
uint64_t sc_volume_volume_size(const sc_volume* v);   /* 数据区字节数（不含头）*/
uint32_t sc_volume_sector_size(const sc_volume* v);
int      sc_volume_is_hidden(const sc_volume* v);

#ifdef __cplusplus
}
#endif

#endif /* SC_VOLUME_H */
