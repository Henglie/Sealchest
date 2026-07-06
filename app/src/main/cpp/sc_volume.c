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

void sc_volume_encrypt_units(sc_volume* v, uint64_t start_unit,
                             uint8_t* buf, uint32_t nbr_units)
{
    if (!v || !v->ci || !buf || nbr_units == 0) return;

    UINT64_STRUCT unitNo;
    unitNo.Value = start_unit;

    EncryptDataUnits((unsigned __int8*) buf, &unitNo, nbr_units, v->ci);
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

/* --- B2 创建容器 --- */

/* 熵注入实现在 sc_random.c（RandgetBytes 从池取）。此处仅声明，链接期解析。 */
extern void sc_random_seed(const uint8_t* entropy, int len);
extern void sc_random_wipe(void);

/* 生成主头 + 备份头（共享同一随机主密钥，各用独立随机盐）。
 *
 * 严格照 Format.c 官方范式（见 Common/Format.c:154 主头 / :658 备份头）：
 *   ① 主头调 CreateVolumeHeaderInMemory，masterKeydata=NULL → 内部 RandgetBytes
 *      生成随机主密钥 + 随机盐，派生 header key，就地加密头，返回成品 512B。
 *      同时经 retInfo 出 cryptoInfo，其 master_keydata 持有刚生成的主密钥。
 *   ② 备份头再调一次，masterKeydata = 第一次的 cryptoInfo->master_keydata
 *      → 复用同一主密钥（这样主备两头解开的是同一个卷），但内部仍 RandgetBytes
 *      取新盐 → 备份头 salt 与主头不同（VC 就是这样，两头盐独立）。
 *
 * bBoot=FALSE（非系统盘）；mode=FIRST_MODE_OF_OPERATION_ID(=1, XTS)；
 * hiddenVolumeSize=0（非隐藏卷，C 阶段再做）；requiredProgramVersion=0；
 * headerFlags=0；sectorSize=512；bWipeMode=FALSE。均与官方非隐藏卷创建一致。 */
int sc_volume_create_headers(uint8_t* out_primary, uint8_t* out_backup,
                             int ea, int prf, int pim,
                             const uint8_t* password, int password_len,
                             uint64_t volume_size, uint64_t encrypted_area_start)
{
    if (!out_primary || !out_backup || password_len < 0 || password_len > MAX_PASSWORD)
        return ERR_PARAMETER_INCORRECT;
    if (prf == 0)   /* 创建必须指定确定的 PRF，不能 auto */
        return ERR_PARAMETER_INCORRECT;

    /* 组装 Password（栈上，用完抹）。 */
    Password pw;
    memset(&pw, 0, sizeof(pw));
    pw.Length = (unsigned __int32) password_len;
    if (password_len > 0)
        memcpy(pw.Text, password, (size_t) password_len);

    unsigned char primary[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
    unsigned char backup[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
    memset(primary, 0, sizeof(primary));
    memset(backup, 0, sizeof(backup));

    PCRYPTO_INFO ci = NULL;
    PCRYPTO_INFO ciBackup = NULL;   /* 备份头调用的 retInfo，内部会 crypto_open 出新块，cleanup 统一关 */
    int retVal = ERR_SUCCESS;

    /* ① 主头：masterKeydata=NULL → 生成新随机主密钥。 */
    int err = CreateVolumeHeaderInMemory(
        NULL,                               /* hwndDlg（无 UI，NULL）*/
        FALSE,                              /* bBoot */
        (char*) primary,                    /* header out */
        ea,
        FIRST_MODE_OF_OPERATION_ID,         /* mode = XTS */
        &pw,
        prf,
        pim,
        NULL,                               /* masterKeydata=NULL → 新密钥 */
        &ci,                                /* retInfo */
        volume_size,                        /* volumeSize（数据区）*/
        0,                                  /* hiddenVolumeSize=0（非隐藏）*/
        encrypted_area_start,               /* encryptedAreaStart */
        volume_size,                        /* encryptedAreaLength = 数据区全长 */
        0,                                  /* requiredProgramVersion（0=默认）*/
        0,                                  /* headerFlags */
        TC_SECTOR_SIZE_LEGACY,              /* sectorSize = 512 */
        FALSE);                             /* bWipeMode */

    if (err != ERR_SUCCESS || ci == NULL) {
        retVal = (err != ERR_SUCCESS) ? err : ERR_OUTOFMEMORY;
        goto cleanup;
    }

    /* ② 备份头：复用主头的 master_keydata（同一卷），内部取新盐。
     * CreateVolumeHeaderInMemory 内部 crypto_open 会分配新 cryptoInfo 并经 retInfo 回写，
     * 故 ciBackup 会被改指向新块（≠ci），必须在 cleanup 单独 close，否则泄漏 + 密钥残留。 */
    {
        ciBackup = ci;
        int err2 = CreateVolumeHeaderInMemory(
            NULL,
            FALSE,
            (char*) backup,
            ea,
            FIRST_MODE_OF_OPERATION_ID,
            &pw,
            prf,
            pim,
            (char*) ci->master_keydata,     /* 复用主密钥 */
            &ciBackup,
            volume_size,
            0,
            encrypted_area_start,
            volume_size,
            0,
            0,
            TC_SECTOR_SIZE_LEGACY,
            FALSE);

        if (err2 != ERR_SUCCESS) {
            retVal = err2;
            goto cleanup;
        }
    }

    /* 成功：拷出两个 512B 头。 */
    memcpy(out_primary, primary, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
    memcpy(out_backup,  backup,  TC_VOLUME_HEADER_EFFECTIVE_SIZE);

cleanup:
    /* ciBackup 若被备份头调用改指向新块（≠ci），单独关闭抹密钥；==ci 则由下方统一关。 */
    if (ciBackup && ciBackup != ci) crypto_close(ciBackup);
    if (ci) crypto_close(ci);               /* 抹主密钥 */
    burn(&pw, sizeof(pw));
    burn(primary, sizeof(primary));
    burn(backup, sizeof(backup));
    /* 抹熵池：主密钥种子已用完，不留在内存（VC 的 RandStop(freePool) 等价）。 */
    sc_random_wipe();
    return retVal;
}

/* --- B1 改密码 / PIM / PRF ---
 *
 * 严格照 VC ChangePwd（Common/Password.c:190）标准文件容器路径：
 *   主头 + 备份头各调一次 CreateVolumeHeaderInMemory，masterKeydata = 旧卷主密钥
 *   （v->ci->master_keydata，256B）→ 复用同一主密钥（改密码不动数据区），
 *   全部卷参数从旧 cryptoInfo 原样透传，只 password/pkcs5/pim 换新，内部各取新盐。
 *   （Password.c:513-528 那个 hiddenVolumeSize=VolumeSize 的调用是设备级 in-place
 *    加密专用的假隐藏头，bDevice && NONSYS_INPLACE_ENC 分支，文件容器不走 → 此处
 *    两头 hiddenVolumeSize 均传 0，与主头调用一致。）
 */
int sc_volume_rekey_headers(const sc_volume* v,
                            int new_prf, int new_pim,
                            const uint8_t* new_password, int password_len,
                            uint8_t* out_primary, uint8_t* out_backup)
{
    if (!v || !v->ci || !out_primary || !out_backup)
        return ERR_PARAMETER_INCORRECT;
    if (password_len < 0 || password_len > MAX_PASSWORD)
        return ERR_PARAMETER_INCORRECT;

    PCRYPTO_INFO src = v->ci;

    /* new_prf==0 → 保持原卷 PRF（对齐 ChangePwd 的 pkcs5==0 语义）。 */
    int prf = (new_prf != 0) ? new_prf : src->pkcs5;
    if (prf == 0)
        return ERR_PARAMETER_INCORRECT;

    /* 组装新密码（栈上，用完抹）。 */
    Password pw;
    memset(&pw, 0, sizeof(pw));
    pw.Length = (unsigned __int32) password_len;
    if (password_len > 0)
        memcpy(pw.Text, new_password, (size_t) password_len);

    unsigned char primary[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
    unsigned char backup[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
    memset(primary, 0, sizeof(primary));
    memset(backup, 0, sizeof(backup));

    PCRYPTO_INFO ci = NULL;
    PCRYPTO_INFO ciBackup = NULL;
    int retVal = ERR_SUCCESS;

    /* ① 主头：masterKeydata = 旧卷主密钥 → 重加密路径，全部卷参数从 src 透传。 */
    int err = CreateVolumeHeaderInMemory(
        NULL,                               /* hwndDlg */
        FALSE,                              /* bBoot */
        (char*) primary,
        src->ea,
        src->mode,
        &pw,
        prf,
        new_pim,
        (char*) src->master_keydata,        /* 复用旧主密钥（256B）*/
        &ci,
        src->VolumeSize.Value,
        0,                                  /* hiddenVolumeSize=0（标准卷，文件容器）*/
        src->EncryptedAreaStart.Value,
        src->EncryptedAreaLength.Value,
        src->RequiredProgramVersion,        /* 原样保留，勿写死 */
        src->HeaderFlags,                   /* 原样保留 */
        src->SectorSize,                    /* 原样保留 */
        FALSE);                             /* bWipeMode */

    if (err != ERR_SUCCESS || ci == NULL) {
        retVal = (err != ERR_SUCCESS) ? err : ERR_OUTOFMEMORY;
        goto cleanup;
    }

    /* ② 备份头：同参数再调一次，内部取新盐（主/备盐不同，与 VC 一致）。 */
    {
        ciBackup = ci;
        int err2 = CreateVolumeHeaderInMemory(
            NULL,
            FALSE,
            (char*) backup,
            src->ea,
            src->mode,
            &pw,
            prf,
            new_pim,
            (char*) src->master_keydata,
            &ciBackup,
            src->VolumeSize.Value,
            0,
            src->EncryptedAreaStart.Value,
            src->EncryptedAreaLength.Value,
            src->RequiredProgramVersion,
            src->HeaderFlags,
            src->SectorSize,
            FALSE);

        if (err2 != ERR_SUCCESS) {
            retVal = err2;
            goto cleanup;
        }
    }

    memcpy(out_primary, primary, TC_VOLUME_HEADER_EFFECTIVE_SIZE);
    memcpy(out_backup,  backup,  TC_VOLUME_HEADER_EFFECTIVE_SIZE);

cleanup:
    if (ciBackup && ciBackup != ci) crypto_close(ciBackup);
    if (ci) crypto_close(ci);
    burn(&pw, sizeof(pw));
    burn(primary, sizeof(primary));
    burn(backup, sizeof(backup));
    sc_random_wipe();
    return retVal;
}
