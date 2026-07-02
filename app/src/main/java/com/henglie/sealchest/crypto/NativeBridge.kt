package com.henglie.sealchest.crypto

import android.util.Log

/**
 * JNI 桥：Kotlin ↔ VeraCrypt C 解密核心的唯一入口。
 *
 * 暴露三件事：开卷（验密码 + 派生密钥 + 出句柄）、按数据单元解密、关卷。
 * 句柄是 native sc_volume* 的整数形（jlong），Kotlin 侧不透明，用完必须 [closeVolume]。
 *
 * 设计原则：native 加载失败时 [isAvailable] 为 false，UI 显示明确提示而非崩溃。
 * 加解密核心不可回退（VeraCrypt 格式必须由这套 C 实现处理），故无 JDK 回退路径，
 * 只做"可用/不可用"的清晰判定。
 */
object NativeBridge {

    private const val TAG = "SC-NativeBridge"
    private const val LIB_NAME = "sealchest"

    /** XTS 数据单元大小（字节），VeraCrypt 固定 512。 */
    const val UNIT_SIZE = 512

    /** PRF 选择：0 = 依次尝试全部（推荐，兼容任意容器）。 */
    const val PRF_AUTO = 0

    /** native 库是否成功加载且自检通过。 */
    @JvmStatic
    val isAvailable: Boolean

    init {
        isAvailable = try {
            System.loadLibrary(LIB_NAME)
            nativeSelfTest()
        } catch (t: Throwable) {
            Log.w(TAG, "native 库不可用：${t.message}")
            false
        }
    }

    // ---------------- native 声明（实现见 src/main/cpp/native_lib.cpp）----------------

    /** 自检：算一次已知 SHA-256 测试向量比对，确认实现与 ABI 正确。 */
    private external fun nativeSelfTest(): Boolean

    /** 返回 native 核心版本串（含编译期算法集摘要）。 */
    private external fun nativeVersion(): String

    /** 开卷。返回 0 表示失败（密码错/格式不符/参数错），非 0 为句柄。 */
    private external fun nativeOpenVolume(header: ByteArray, password: ByteArray, pim: Int, prf: Int): Long

    /** 原地解密 buf 里的 nbrUnits 个 512B 数据单元，起始单元号 startUnit。 */
    private external fun nativeDecryptUnits(handle: Long, startUnit: Long, buf: ByteArray, nbrUnits: Int)

    /** 关卷：销毁密钥并释放句柄。 */
    private external fun nativeCloseVolume(handle: Long)

    private external fun nativeVolumeEa(handle: Long): Int
    private external fun nativeVolumePrf(handle: Long): Int
    private external fun nativeVolumeSize(handle: Long): Long
    private external fun nativeEncryptedAreaStart(handle: Long): Long
    private external fun nativeVolumeSectorSize(handle: Long): Int
    private external fun nativeVolumeIsHidden(handle: Long): Boolean

    // ---------------- 对上层暴露 ----------------

    /** native 核心版本串。native 不可用时返回占位串。 */
    fun version(): String =
        if (isAvailable) {
            try {
                nativeVersion()
            } catch (t: Throwable) {
                Log.w(TAG, "nativeVersion 失败：${t.message}")
                "unknown"
            }
        } else {
            "unavailable"
        }

    /**
     * 开卷。[header] 为卷起始至少 512 字节（含 salt）；[password] 为 UTF-8 字节（≤128）；
     * [pim] 个人迭代倍数（0 = 默认）；[prf] 见 [PRF_AUTO]。
     * 成功返回 [Volume]，失败返回 null（密码错 / 非 VeraCrypt 卷 / native 不可用）。
     */
    fun openVolume(header: ByteArray, password: ByteArray, pim: Int = 0, prf: Int = PRF_AUTO): Volume? {
        if (!isAvailable) return null
        val h = nativeOpenVolume(header, password, pim, prf)
        return if (h != 0L) Volume(h) else null
    }

    /**
     * 已开启的卷句柄。线程不安全（VeraCrypt 单线程核心），调用方自行串行化。
     * 用完必须 [close]。
     */
    class Volume internal constructor(private var handle: Long) : AutoCloseable {

        val encryptionAlgorithm: Int get() = nativeVolumeEa(handle)
        val prf: Int get() = nativeVolumePrf(handle)
        /** 数据区字节数（不含卷头）。 */
        val volumeSize: Long get() = nativeVolumeSize(handle)
        val encryptedAreaStart: Long get() = nativeEncryptedAreaStart(handle)
        val sectorSize: Int get() = nativeVolumeSectorSize(handle)
        val isHidden: Boolean get() = nativeVolumeIsHidden(handle)

        /**
         * 原地解密 [buf] 中的 [nbrUnits] 个 512B 数据单元，起始 XTS 单元号 [startUnit]。
         * [buf] 长度须 ≥ [nbrUnits] * [UNIT_SIZE]。
         *
         * 单元号语义（真容器实测坐实，见 PROGRESS 踩坑）：**文件绝对偏移 / 512**，
         * 不是数据区相对。数据区第一扇区在文件偏移 [encryptedAreaStart] 处，其单元号
         * = [encryptedAreaStart] / 512。故读容器内逻辑偏移 L（0 = 数据区首扇区）时，
         * 密文取自文件偏移 [encryptedAreaStart] + L，单元号 = ([encryptedAreaStart] + L) / 512。
         * 这套映射封在 VolumeReader 里，FAT 层只见逻辑偏移。
         */
        fun decryptUnits(startUnit: Long, buf: ByteArray, nbrUnits: Int) {
            check(handle != 0L) { "卷已关闭" }
            nativeDecryptUnits(handle, startUnit, buf, nbrUnits)
        }

        override fun close() {
            if (handle != 0L) {
                nativeCloseVolume(handle)
                handle = 0L
            }
        }
    }
}
