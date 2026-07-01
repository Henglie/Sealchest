/* ============================================================
 *  密匣 Sealchest · 开卷/解扇区正确性验证器（独立可执行，非 JNI）
 *
 *  只 include 纯净门面 sc_volume.h，与 JNI 层走同一条 C API。
 *  用官方 VeraCrypt 测试容器（third_party/VeraCrypt/Tests/test.*.hc，
 *  密码见 bench.bat：普通卷 test / 隐藏卷 testhidden）验证：
 *    1. 开卷成功（PBKDF2 派生 + 卷头解密 + magic 校验）
 *    2. PRF 自动检测（prf=0 遍历命中）
 *    3. 数据区第 0 单元解密正确（FAT 引导扇区末尾必 0x55 0xAA）
 *
 *  这一步的意义：sc_volume 的偏移语义（EncStart / data unit 0）此前是
 *  纯推断，本验证器用真容器坐实。用 NDK 交叉编到 x86_64-linux-android，
 *  推模拟器跑，环境等于最终 ABI 之一。
 *
 *  编译（在 cpp/ 目录，需 NDK android.toolchain.cmake）：见 PROGRESS 说明。
 *  运行：adb push sc_test + *.hc 到 /data/local/tmp，
 *        ./sc_test <container.hc> <password> [pim] [prf]
 * ============================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sc_volume.h"

static void hexdump(const uint8_t* p, int n) {
    for (int i = 0; i < n; i++) {
        printf("%02x", p[i]);
        if ((i & 15) == 15) printf("\n");
        else                printf(" ");
    }
    if (n & 15) printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <container.hc> <password> [pim] [prf]\n", argv[0]);
        return 2;
    }
    const char* path = argv[1];
    const char* pw   = argv[2];
    int pim = argc > 3 ? atoi(argv[3]) : 0;
    int prf = argc > 4 ? atoi(argv[4]) : 0;   /* 0 = 自动遍历全部 PRF */

    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 512) { fprintf(stderr, "file too small\n"); fclose(f); return 2; }
    uint8_t* data = (uint8_t*) malloc((size_t) sz);
    if (!data) { fclose(f); return 2; }
    if (fread(data, 1, (size_t) sz, f) != (size_t) sz) { perror("fread"); fclose(f); free(data); return 2; }
    fclose(f);

    printf("=== %s (pw=\"%s\" pim=%d prf=%d) size=%ld ===\n", path, pw, pim, prf, sz);

    int err = 0;
    sc_volume* v = sc_volume_open(data, (const uint8_t*) pw, (int) strlen(pw), pim, prf, &err);
    if (!v) { printf("[FAIL] open failed err=%d\n", err); free(data); return 1; }

    uint64_t eas = sc_volume_encrypted_area_start(v);
    uint64_t vsz = sc_volume_volume_size(v);
    uint32_t ss  = sc_volume_sector_size(v);
    printf("[ OK ] open  ea=%d prf=%d EncStart=%llu VolSize=%llu SectorSize=%u\n",
           sc_volume_ea(v), sc_volume_prf(v),
           (unsigned long long) eas, (unsigned long long) vsz, ss);

    if (eas + 512 > (uint64_t) sz) {
        printf("[FAIL] EncryptedAreaStart(%llu)+512 超出文件\n", (unsigned long long) eas);
        sc_volume_close(v); free(data); return 1;
    }

    /* 数据区第一个扇区在文件里的偏移 = EncryptedAreaStart。取密文 512B。
     * 待验的未知量是 XTS 单元号语义：这第一个扇区的 tweak 该传几？
     * 两种主流约定：
     *   A. 单元号从数据区起始重新计数 → 第一扇区 = 0
     *   B. 单元号沿用文件绝对扇区号   → 第一扇区 = EncryptedAreaStart/512
     * 逐一试，用 FAT 引导签名 0x55AA 当判据，命中即坐实语义。 */
    const uint64_t cand[2] = { 0, eas / 512 };
    const char*    desc[2] = { "0 (数据区相对)", "EncStart/512 (文件绝对)" };

    int hit = -1;
    uint8_t sec[512];
    for (int c = 0; c < 2; c++) {
        memcpy(sec, data + eas, 512);
        sc_volume_decrypt_units(v, cand[c], sec, 1);
        int ok = (sec[510] == 0x55 && sec[511] == 0xAA);
        printf("--- 试 startUnit=%llu [%s] sig[510..511]=%02x %02x %s\n",
               (unsigned long long) cand[c], desc[c],
               sec[510], sec[511], ok ? "命中" : "不符");
        if (ok) { hit = c; break; }
    }

    if (hit < 0) {
        printf("[FAIL] 两种单元号语义都未命中引导签名，解密或偏移有误\n");
        printf("--- startUnit=0 解出的前 32 字节（供人工诊断）---\n");
        memcpy(sec, data + eas, 512);
        sc_volume_decrypt_units(v, 0, sec, 1);
        hexdump(sec, 32);
        sc_volume_close(v); free(data);
        return 1;
    }

    /* 命中：重解一次该语义，打印引导扇区细节坐实。 */
    memcpy(sec, data + eas, 512);
    sc_volume_decrypt_units(v, cand[hit], sec, 1);
    printf("--- data unit (startUnit=%llu) 前 32 字节 ---\n", (unsigned long long) cand[hit]);
    hexdump(sec, 32);
    printf("OEM name [3..10] = \"");
    for (int i = 3; i < 11; i++) putchar((sec[i] >= 32 && sec[i] < 127) ? sec[i] : '.');
    printf("\"\n");

    sc_volume_close(v);
    free(data);

    printf("[PASS] 解扇区正确，XTS 单元号语义 = %s\n", desc[hit]);
    return 0;
}
