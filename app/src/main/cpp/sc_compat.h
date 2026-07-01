/* ============================================================
 *  密匣 Sealchest · VeraCrypt C 核心平台适配垫片
 *
 *  force-include（-include）到所有 VeraCrypt .c 源之前，先于 config.h /
 *  Tcdefs.h 生效。作用有二：
 *    1. 摁死全部汇编 / SIMD / 硬件加速路径，强制纯 C 单线程回退。
 *    2. 补齐 VeraCrypt 只在 Windows 分支定义、却被非 boot 代码引用的类型与
 *       Win32 API —— 这些引用集中在写卷路径与多线程密钥派生死代码里，只读
 *       路径永不执行，桩到能链接即可。
 *
 *  只对 veracrypt/ 那批源生效（见 CMakeLists 的 veracrypt_core 静态库），
 *  不污染 native_lib.cpp / sha256.cpp。
 * ============================================================ */
#ifndef SC_COMPAT_H
#define SC_COMPAT_H

/* ---- 字节序：抢在 VeraCrypt Endian.h 之前定义 ----------------------
 * Windows 文件系统大小写不敏感，Endian.h 第 42 行 `#include <endian.h>`
 * （Linux 系统头）会命中同目录的 Endian.h 自身 → 自引用，BYTE_ORDER 探测
 * 失败报 `Byte order cannot be determined`。这里预定义 BYTE_ORDER 家族，
 * 让 Endian.h 的 `#ifndef BYTE_ORDER` 整块跳过。Android 全平台小端。
 * LITTLE_ENDIAN/BIG_ENDIAN 也一并补，Xts.h/misc.h 的 `#if BYTE_ORDER==...` 要用。 */
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* ---- 关掉 x86 汇编 / SSE / AES-NI ----------------------------------
 * config.h 里 SSE2/SSSE3 intrinsics 仅受 CRYPTOPP_DISABLE_SSE* 管，
 * DISABLE_ASM 挡不住。x86_64 上 __SSE2__ 默认开、HasSSE2() 恒为 1，
 * 不关就会拉 serpent_simd_* / kuznyechik_*_simd / blake2s_compress_sse*
 * 等未编入的符号。 */
#ifndef CRYPTOPP_DISABLE_ASM
#define CRYPTOPP_DISABLE_ASM 1
#endif
#ifndef CRYPTOPP_DISABLE_SSE2
#define CRYPTOPP_DISABLE_SSE2 1
#endif
#ifndef CRYPTOPP_DISABLE_SSSE3
#define CRYPTOPP_DISABLE_SSSE3 1
#endif
#ifndef CRYPTOPP_DISABLE_AESNI
#define CRYPTOPP_DISABLE_AESNI 1
#endif
/* Intel SHA 扩展（SHA-NI）：SHANI_AVAILABLE 只看 !DISABLE_SHANI + X64 +
 * clang 版本，跟 DISABLE_ASM 无关。不关它，cpu.c:372 会引用 Sha2Intel.c 的
 * TrySHA256（未编入）→ 链接缺符号。x86_64 ABI 与本地 x86 测试器都踩此坑，
 * 关掉走纯软 Sha2.c。 */
#ifndef CRYPTOPP_DISABLE_SHANI
#define CRYPTOPP_DISABLE_SHANI 1
#endif

/* ---- 关掉 ARMv8 crypto / NEON intrinsics ---------------------------
 * ARM 侧走 __ARM_FEATURE_CRYPTO + 编译器版本触发，同样不归 DISABLE_ASM 管。
 * 关掉后 IsAesHwCpuSupported() 走 HasAESNI()==g_hasAESARM，未探测默认 0，
 * 恒返回纯软路径，aes_hw_cpu_* 桩永不执行。 */
#ifndef CRYPTOPP_DISABLE_ARM_AES
#define CRYPTOPP_DISABLE_ARM_AES 1
#endif
#ifndef CRYPTOPP_DISABLE_ARM_SHA
#define CRYPTOPP_DISABLE_ARM_SHA 1
#endif
#ifndef CRYPTOPP_DISABLE_ARM_ASIMD
#define CRYPTOPP_DISABLE_ARM_ASIMD 1
#endif

/* ---- Argon2 强制单线程 --------------------------------------------
 * mt 版整段随 ARGON2_NO_THREADS 排除，免 argon2_thread_create/join 等
 * 平台线程符号；fill_memory_blocks 走单线程 _st 版。 */
#ifndef ARGON2_NO_THREADS
#define ARGON2_NO_THREADS 1
#endif

/* ---- 补 Windows 分支独有、POSIX 分支缺失的类型 ----------------------
 * Tcdefs.h 的 !_MSC_VER 分支不定义这些，但 EncryptionThreadPool.h /
 * Volumes.c 的死代码会用到。用标准整型对齐语义即可（纯本地死代码，
 * LP64 下 long 宽度差异不影响只读路径正确性）。 */
#include <stdint.h>

/* Tcdefs.h 的 POSIX 分支把 __int8/16/32 定成宏，却漏了 __int64；而 Xts.h:52
 * `typedef unsigned __int64 TC_LARGEST_COMPILER_UINT` 与 Crypto 各处都用它。
 * 其 `#ifndef TC_LARGEST_COMPILER_UINT` 守卫看不见 Tcdefs 的 typedef（预处理器
 * 对 typedef 盲），故该行会执行 → 撞未定义的 __int64，连锁炸穿 Xts.c/Volumes.h。
 * 这里补上宏。关键：必须与 uint64（=uint64_t）的底层类型一致，否则
 * `unsigned __int64` 与 uint64 撞 typedef 重定义。arm64/Linux 下 int64_t
 * 是 long、ILP32 下是 long long → 用 clang 内建 __INT64_TYPE__ 精确对齐。 */
#ifndef __int64
#define __int64 __INT64_TYPE__
#endif

typedef long           LONG;   /* Win32 LONG 语义，配合 InterlockedExchangeAdd */
typedef unsigned long  ULONG;  /* Crypto.c:1285 AllocTag 死代码用 */
typedef unsigned short WORD;   /* GetCpuCount(WORD*) 用 */
typedef unsigned long  DWORD;  /* 写卷 I/O 死代码用 */
typedef void*          HANDLE;
typedef void*          HWND;
typedef void*          TC_EVENT; /* 实为 HANDLE，只读路径不派发事件 */

typedef union {
    struct { DWORD LowPart; LONG HighPart; };
    int64_t QuadPart;
} LARGE_INTEGER;

/* ReadEffectiveVolumeHeader/WriteEffectiveVolumeHeader（设备 I/O 死代码，
 * 只读开卷走内存 buffer，不碰这条路）用到的 Windows 磁盘几何结构。
 * 只需 BytesPerSector 字段能编过即可。 */
typedef struct {
    unsigned long BytesPerSector;
} DISK_GEOMETRY;

/* 同上死代码里的 max/min（Windows 由 windows.h 提供）。 */
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* ---- 桩掉内存锁 / 事件 / 原子 / 写卷 I/O 等 Win32 API --------------
 * 全部落在写卷或多线程派生死代码里，只读开卷路径不触及。 */
#define VirtualLock(addr, size)          ((void)0)
#define VirtualUnlock(addr, size)        ((void)0)
#define CreateEvent(sa, manual, init, nm) ((HANDLE)0)
#define CloseHandle(h)                   ((void)0)
#define InterlockedExchangeAdd(p, v)     ((*(p)) += (v), (*(p)) - (v))
#define InterlockedExchange(p, v)        (*(p) = (v))
#define TC_WAIT_EVENT(evt)               ((void)0)

/* Crypto.c 的 HashGetName/EAGetName 用 _wcsicmp 大小写无关比宽字符串；
 * NDK 提供等价的 wcscasecmp。 */
#include <wchar.h>
#define _wcsicmp wcscasecmp

/* HasRDRAND/HasRDSEED：cpu.h 只在 x86 分支把它们定成宏，ARMV8 分支没有 →
 * ARM 上 Crypto.c:1211 `HasRDSEED()||HasRDRAND()`（其 #ifndef _M_ARM64 守卫
 * 在 Android 不生效）变成未定义调用。仅在 ARM 补 0 宏，x86 留给 cpu.h。
 * RDRAND/RDSEED 是 CPU 硬件随机数，只读开卷不需要。 */
#if defined(__aarch64__) || defined(__arm__)
#define HasRDRAND() 0
#define HasRDSEED() 0
#endif

#ifndef FILE_BEGIN
#define FILE_BEGIN 0
#endif
#ifndef FILE_CURRENT
#define FILE_CURRENT 1
#endif
#ifndef ERROR_INVALID_PARAMETER
#define ERROR_INVALID_PARAMETER 87
#endif
#ifndef IOCTL_DISK_GET_DRIVE_GEOMETRY
#define IOCTL_DISK_GET_DRIVE_GEOMETRY 0
#endif

#define SetFilePointerEx(h, off, newp, method) (0)
#define ReadFile(h, buf, n, done, ov)          (0)
#define WriteFile(h, buf, n, done, ov)         (0)
#define DeviceIoControl(h, code, ib, ibs, ob, obs, ret, ov) (0)
#define SetLastError(e)                        ((void)0)
#define GetLastError()                         (0)

#endif /* SC_COMPAT_H */
