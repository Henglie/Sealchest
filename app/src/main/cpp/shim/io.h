/* ============================================================
 *  密匣 Sealchest · <io.h> 垫片（Android 无此 Windows 头）
 *
 *  Volumes.c:26 无条件 `#include <io.h>`，但只读开卷路径不调用任何
 *  <io.h> 的低级函数（_open/_read 等只在写卷路径，已被 RNG/IO 桩挡掉）。
 *  空头即可让 Volumes.c 编过。仅 veracrypt_core 的 include 路径能命中。
 * ============================================================ */
#ifndef SC_SHIM_IO_H
#define SC_SHIM_IO_H
#endif /* SC_SHIM_IO_H */
