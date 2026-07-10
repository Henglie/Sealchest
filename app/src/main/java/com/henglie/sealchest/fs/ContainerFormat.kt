package com.henglie.sealchest.fs

/**
 * 容器格式探测（X7）。**只探测魔数、绝不解密**——匿匣守本心：是严格的 VeraCrypt
 * 容器解析器，不做别家格式的解锁。本探测器唯一职责是：当一个文件开卷失败时，判断它
 * 是不是某种「已知但我们不支持」的加密容器（当前仅 LUKS），从而给用户一句针对性提示
 * （「检测到 LUKS 容器，暂不支持」），而非笼统的「密码错误」误导用户反复试密码。
 *
 * 为什么不解密 LUKS：LUKS 解锁涉及独立的密钥槽 / Argon2 派生 / dm-crypt 语义，属另一条
 * 产品线，需恒烈单独立项定夺。本卡只做「友好识别」，不越界。
 */
object ContainerFormat {

    /**
     * LUKS1 / LUKS2 的公共魔数：偏移 0 起 6 字节 `4C 55 4B 53 BA BE`（"LUKS\xba\xbe"）。
     * 两版本共用同一魔数，版本号在偏移 6 的 2 字节大端（1=LUKS1，2=LUKS2）。
     */
    private val LUKS_MAGIC = byteArrayOf(0x4C, 0x55, 0x4B, 0x53, 0xBA.toByte(), 0xBE.toByte())

    /**
     * 探测 [rawHeader]（容器文件偏移 0 起的原始字节，未解密）是否为 LUKS 容器。
     * [rawHeader] 至少需 8 字节；不足或不匹配返回 false。
     */
    fun isLuks(rawHeader: ByteArray): Boolean {
        if (rawHeader.size < LUKS_MAGIC.size) return false
        for (i in LUKS_MAGIC.indices) {
            if (rawHeader[i] != LUKS_MAGIC[i]) return false
        }
        return true
    }

    /**
     * 取 LUKS 版本号（偏移 6 的 2 字节大端）。非 LUKS 或长度不足返回 0。
     * 仅用于提示文案区分 LUKS1/LUKS2，不影响处理逻辑。
     */
    fun luksVersion(rawHeader: ByteArray): Int {
        if (!isLuks(rawHeader) || rawHeader.size < 8) return 0
        return ((rawHeader[6].toInt() and 0xFF) shl 8) or (rawHeader[7].toInt() and 0xFF)
    }
}

/**
 * 开卷失败时，若识别出是「已知但不支持」的容器格式（如 LUKS），抛此异常携带针对性提示。
 * 与 [SecurityException]（密码/PIM/PRF/keyfile 错误）区分开，UI 据类型给不同引导。
 */
class UnsupportedContainerException(message: String) : Exception(message)
