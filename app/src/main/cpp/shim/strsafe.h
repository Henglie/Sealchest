/* ============================================================
 *  密匣 Sealchest · <strsafe.h> 垫片（Android 无此 Windows 头）
 *
 *  Crypto.c:26 在非 driver 分支 `#include <strsafe.h>`，用到的只有
 *  StringCchCopyW / StringCchCatW 两个宽字符函数（见 EAGetName /
 *  HashGetName2，产出算法显示名）。这里用 NDK 的 wcslcpy/wcslcat
 *  语义补齐 —— 有界拷贝/拼接，签名对齐 Win32 (dest, cchDest, src)。
 *  仅 veracrypt_core 的 include 路径能命中，不外泄。
 * ============================================================ */
#ifndef SC_SHIM_STRSAFE_H
#define SC_SHIM_STRSAFE_H

#include <wchar.h>
#include <stddef.h>

/* Win32 StringCchCopyW(dest, cchDest, src)：把 src 拷进 dest，最多
 * cchDest 个 wchar_t（含结尾 NUL），保证 NUL 结尾。 */
static inline void StringCchCopyW(wchar_t* dest, size_t cchDest, const wchar_t* src)
{
    if (!dest || cchDest == 0) return;
    size_t i = 0;
    for (; src && src[i] && i < cchDest - 1; ++i)
        dest[i] = src[i];
    dest[i] = L'\0';
}

/* Win32 StringCchCatW(dest, cchDest, src)：把 src 拼到 dest 尾部，
 * 总长（含 NUL）不超过 cchDest。 */
static inline void StringCchCatW(wchar_t* dest, size_t cchDest, const wchar_t* src)
{
    if (!dest || cchDest == 0) return;
    size_t len = 0;
    while (len < cchDest && dest[len]) ++len;
    if (len >= cchDest - 1) return;
    size_t i = 0;
    for (; src && src[i] && (len + i) < cchDest - 1; ++i)
        dest[len + i] = src[i];
    dest[len + i] = L'\0';
}

#endif /* SC_SHIM_STRSAFE_H */
