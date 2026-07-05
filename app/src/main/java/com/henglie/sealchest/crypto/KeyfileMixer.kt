package com.henglie.sealchest.crypto

/**
 * VeraCrypt keyfile 混入算法（纯 Kotlin 复刻，与 C 版 KeyFilesApply 字节级一致）。
 *
 * 原 C 版（third_party/VeraCrypt/src/Common/Keyfiles.c）满是 Windows I/O
 * （CreateFile/_wfindfirst/SecurityToken/C++ vector），无法直接编入。但混入算法本身极简：
 * 标准 CRC32（多项式 0xEDB88320，初值 0xFFFFFFFF，滚动不取反）逐字节滚动，
 * 每字节把 4 字节 big-endian CRC 中间值模加进 keyPool，池满按 keyPoolSize 回绕，
 * 单文件上限 1 MiB，最后 password[i] += pool[i]（i<len）或 = pool[i]（i≥len）。
 *
 * 关键不变量（必须与 C 版逐字节对齐，错一 bit 容器永远打不开）：
 * - keyPool 数组恒 [KEYFILE_POOL_SIZE]=128 字节；writePos 按 keyPoolSize 回绕。
 *   keyPoolSize = 密码长度 ≤ 64 时取 64（LEGACY），否则 128。
 * - keyPoolSize 恒为 4 的倍数（64/128），writePos 每字节步进 4，故循环顶恒是 4 的
 *   倍数，写到 keyPoolSize-1 后正好回绕 → **永不越界**，无需靠数组尾部余量兜底。
 * - 每个 keyfile 独立重置 crc/writePos，只经 += 累加进共享池 → keyfile 顺序无关
 *   （加法交换律），多选文件顺序不影响结果。
 */
object KeyfileMixer {

    const val KEYFILE_POOL_SIZE = 128
    const val KEYFILE_POOL_LEGACY_SIZE = 64
    const val KEYFILE_MAX_READ_LEN = 1024 * 1024
    const val MAX_LEGACY_PASSWORD = 64

    /** 标准 CRC32 表（多项式 0xEDB88320），与 VeraCrypt crc_32_tab 一致，运行期生成。 */
    private val crc32Tab: IntArray = IntArray(256).also { tab ->
        for (n in 0 until 256) {
            var c = n
            repeat(8) { c = if (c and 1 != 0) 0xEDB88320.toInt() xor (c ushr 1) else c ushr 1 }
            tab[n] = c
        }
    }

    /** UPDC32：tab[(crc ^ octet) & 0xff] ^ (crc >>> 8)。crc/返回值按 u32 语义。 */
    private fun updc32(octet: Int, crc: Int): Int =
        crc32Tab[(crc xor octet) and 0xff] xor (crc ushr 8)

    /**
     * 把 [keyfiles]（每项是一个 keyfile 的完整字节内容）混入 [password]，返回新的有效密码字节。
     * 不修改入参 [password]（调用方负责抹除原副本）。无 keyfile 时原样返回 password 的拷贝。
     *
     * @param password 用户输入的密码 UTF-8 字节（可空长度 0）
     * @param keyfiles keyfile 内容列表，每个已由 SAF 读入内存（超 1 MiB 部分本函数内截断）
     */
    fun apply(password: ByteArray, keyfiles: List<ByteArray>): ByteArray {
        if (keyfiles.isEmpty()) return password.copyOf()

        val keyPool = IntArray(KEYFILE_POOL_SIZE) // 用 Int 存 0..255，避免 Byte 有符号加法坑
        val keyPoolSize =
            if (password.size <= MAX_LEGACY_PASSWORD) KEYFILE_POOL_LEGACY_SIZE else KEYFILE_POOL_SIZE

        for (kf in keyfiles) {
            var crc = -1 // 0xFFFFFFFF
            var writePos = 0
            val limit = minOf(kf.size, KEYFILE_MAX_READ_LEN)
            for (i in 0 until limit) {
                crc = updc32(kf[i].toInt() and 0xff, crc)
                // 4 字节 big-endian 依次模加进池（C 版 keyPool[writePos++] += ...）。
                keyPool[writePos] = (keyPool[writePos] + ((crc ushr 24) and 0xff)) and 0xff; writePos++
                keyPool[writePos] = (keyPool[writePos] + ((crc ushr 16) and 0xff)) and 0xff; writePos++
                keyPool[writePos] = (keyPool[writePos] + ((crc ushr 8) and 0xff)) and 0xff; writePos++
                keyPool[writePos] = (keyPool[writePos] + (crc and 0xff)) and 0xff; writePos++
                if (writePos >= keyPoolSize) writePos = 0
            }
        }

        // 混入密码：i<len 累加，i≥len 直接赋值；长度不足则抬到 keyPoolSize。
        val outLen = maxOf(password.size, keyPoolSize)
        val out = ByteArray(outLen)
        for (i in password.indices) out[i] = password[i]
        for (i in 0 until keyPoolSize) {
            val v = if (i < password.size) (out[i].toInt() and 0xff) + keyPool[i] else keyPool[i]
            out[i] = (v and 0xff).toByte()
        }
        // password.Length < keyPoolSize 时 Length 抬到 keyPoolSize —— out 已是该长度。
        return out
    }
}
