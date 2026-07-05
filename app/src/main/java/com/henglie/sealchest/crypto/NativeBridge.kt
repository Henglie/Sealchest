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

    /** 原地加密 buf 里的 nbrUnits 个 512B 数据单元，起始单元号 startUnit（写入互通用）。 */
    private external fun nativeEncryptUnits(handle: Long, startUnit: Long, buf: ByteArray, nbrUnits: Int)

    /** 关卷：销毁密钥并释放句柄。 */
    private external fun nativeCloseVolume(handle: Long)

    private external fun nativeVolumeEa(handle: Long): Int
    private external fun nativeVolumePrf(handle: Long): Int
    private external fun nativeVolumeSize(handle: Long): Long
    private external fun nativeEncryptedAreaStart(handle: Long): Long
    private external fun nativeVolumeSectorSize(handle: Long): Int
    private external fun nativeVolumeIsHidden(handle: Long): Boolean

    /** 灌熵：把 Kotlin SecureRandom 的字节注入 native 随机池（B2 建卷前调）。 */
    private external fun nativeSeedRandom(entropy: ByteArray)

    /**
     * 生成一对 VeraCrypt 卷头（主头 + 备份头，共享随机主密钥、各用独立随机盐）。
     * outPrimary / outBackup 各须 ≥512B，成功就地写入 512B 有效头。
     * 返回 0 = 成功（ERR_SUCCESS），非 0 = VeraCrypt ERR_* 码（熵不足 / 弱密钥 / 参数错）。
     */
    private external fun nativeCreateHeaders(
        outPrimary: ByteArray, outBackup: ByteArray,
        ea: Int, prf: Int, pim: Int, password: ByteArray,
        volumeSize: Long, encStart: Long,
    ): Int

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
     * B2 灌熵：把 Kotlin SecureRandom（Android CSPRNG）产生的熵注入 native 随机池。
     * 生成卷头前必须先灌足量（一次卷头最多需 主密钥 128B + 盐 64B，建议 ≥4KB）。
     * native 侧一次用尽即弃、取过即抹；池不足时 [createVolumeHeaders] 明确失败，绝不吐可预测随机。
     * 本方法调用后会清零 [entropy]，调用方仍应自行 fill(0) 兜底。
     */
    fun seedRandom(entropy: ByteArray) {
        if (!isAvailable) return
        nativeSeedRandom(entropy)
    }

    /**
     * B2 生成一对 VeraCrypt 卷头（主头 + 备份头，共享随机主密钥、各用独立随机盐）。
     * 调官方 `CreateVolumeHeaderInMemory`，字节级与桌面 VC 一致。**调用前须先 [seedRandom] 灌足熵**。
     *
     * @param password keyfile 混入后的有效密码 UTF-8 字节（可空长度 0）。调用后 native 侧副本已抹，调用方仍应 fill(0)。
     * @param ea 加密算法 ID（AES=1…级联另计）；@param prf PRF ID（不可为 0，须指定）；@param pim。
     * @param volumeSize 数据区字节数（不含头组）；@param encStart 数据区起始（标准 131072）。
     * @return Pair(主头 512B, 备份头 512B)，失败返回 null（熵不足 / 弱密钥 / 参数错 / native 不可用）。
     */
    fun createVolumeHeaders(
        ea: Int, prf: Int, pim: Int, password: ByteArray,
        volumeSize: Long, encStart: Long,
    ): Pair<ByteArray, ByteArray>? {
        if (!isAvailable) return null
        val primary = ByteArray(512)
        val backup = ByteArray(512)
        val err = nativeCreateHeaders(primary, backup, ea, prf, pim, password, volumeSize, encStart)
        if (err != 0) {
            primary.fill(0); backup.fill(0)
            return null
        }
        return primary to backup
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

        /**
         * 原地加密 [buf] 中的 [nbrUnits] 个 512B 数据单元，起始 XTS 单元号 [startUnit]。
         * 单元号语义同 [decryptUnits]（文件绝对偏移 / 512）。与解密严格互逆：
         * 明文 → 加密 → 密文 → 解密 → 原明文。写入路径用此把明文加密成可回写容器的密文。
         *
         * 写入互通的根基（二期）：VolumeReader.write 读-改-写时靠它把改后的明文单元
         * 重新加密。native 双向能力已由 sc_test.c 的往返自测覆盖。
         */
        fun encryptUnits(startUnit: Long, buf: ByteArray, nbrUnits: Int) {
            check(handle != 0L) { "卷已关闭" }
            nativeEncryptUnits(handle, startUnit, buf, nbrUnits)
        }

        override fun close() {
            if (handle != 0L) {
                nativeCloseVolume(handle)
                handle = 0L
            }
        }
    }
}
