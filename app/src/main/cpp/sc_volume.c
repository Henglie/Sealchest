/* ============================================================
 *  密匣 Sealchest · VeraCrypt 卷操作门面实现
 *
 *  编在 veracrypt_core 静态库里 → force-include sc_compat.h 生效，
 *  可安全 include VeraCrypt 头。对外只暴露 sc_volume.h 的纯净 C API，
 *  把 Tcdefs/Crypto/Volumes 等头封在本编译单元内，不外泄给 JNI 层。
 * ============================================================ */
#include "Tcdefs.h"
#include "Crypto.h"
#include "Volumes.h"
#include "Password.h"

#include <stdlib.h>
#include <string.h>

#include "sc_volume.h"

/* 句柄即 PCRYPTO_INFO 的薄封装 —— 保持 sc_volume 对外不透明。 */
struct sc_volume {
    PCRYPTO_INFO ci;
};

sc_volume* sc_volume_open(const uint8_t* header512,
                          const uint8_t* password, int password_len,
                          int pim, int prf, int* out_err)
{
    if (out_err) *out_err = ERR_PARAMETER_INCORRECT;
    if (!header512 || !password || password_len < 0 || password_len > MAX_PASSWORD)
        return NULL;

    /* 组装 Password 结构（栈上，用完立即抹）。 */
    Password pw;
    memset(&pw, 0, sizeof(pw));
    pw.Length = (unsigned __int32) password_len;
    memcpy(pw.Text, password, (size_t) password_len);

    /* ReadVolumeHeaderWithAbort 吃内存 buffer，不碰文件 I/O。
     * bBoot=FALSE（非系统盘）；retInfo 收句柄；retHeaderCryptoInfo=NULL；
     * 两个 abort 指针传 NULL（不支持中断，单线程派生一次跑完）。 */
    PCRYPTO_INFO ci = NULL;
    unsigned char hdr[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
    memcpy(hdr, header512, TC_VOLUME_HEADER_EFFECTIVE_SIZE);

    int err = ReadVolumeHeaderWithAbort(
        FALSE, hdr, &pw, prf, pim, &ci, NULL, NULL, NULL);

    /* 敏感栈缓冲抹除。 */
    burn(&pw, sizeof(pw));
    burn(hdr, sizeof(hdr));

    if (out_err) *out_err = err;
    if (err != ERR_SUCCESS || ci == NULL) {
        if (ci) crypto_close(ci);
        return NULL;
    }

    sc_volume* v = (sc_volume*) malloc(sizeof(sc_volume));
    if (!v) {
        crypto_close(ci);
        if (out_err) *out_err = ERR_OUTOFMEMORY;
        return NULL;
    }
    v->ci = ci;
    return v;
}

void sc_volume_decrypt_units(sc_volume* v, uint64_t start_unit,
                             uint8_t* buf, uint32_t nbr_units)
{
    if (!v || !v->ci || !buf || nbr_units == 0) return;

    UINT64_STRUCT unitNo;
    unitNo.Value = start_unit;

    DecryptDataUnits((unsigned __int8*) buf, &unitNo, nbr_units, v->ci);
}

void sc_volume_close(sc_volume* v)
{
    if (!v) return;
    if (v->ci) crypto_close(v->ci);   /* crypto_close 内部已抹密钥 */
    free(v);
}

/* --- 只读 getter --- */
int sc_volume_ea(const sc_volume* v)  { return (v && v->ci) ? v->ci->ea : 0; }
int sc_volume_prf(const sc_volume* v) { return (v && v->ci) ? v->ci->pkcs5 : 0; }

uint64_t sc_volume_encrypted_area_start(const sc_volume* v)
{
    return (v && v->ci) ? v->ci->EncryptedAreaStart.Value : 0;
}
uint64_t sc_volume_volume_size(const sc_volume* v)
{
    return (v && v->ci) ? v->ci->VolumeSize.Value : 0;
}
uint32_t sc_volume_sector_size(const sc_volume* v)
{
    return (v && v->ci) ? v->ci->SectorSize : 0;
}
int sc_volume_is_hidden(const sc_volume* v)
{
    return (v && v->ci) ? (v->ci->hiddenVolume ? 1 : 0) : 0;
}
