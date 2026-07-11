package com.henglie.sealchest.benchmark

import com.henglie.sealchest.crypto.NativeBridge
import java.security.SecureRandom

/**
 * 单条基准测试结果：算法 ID、显示名、吞吐速度（MB/s）。
 */
data class BenchResult(val eaId: Int, val name: String, val speedMBps: Double)

/**
 * VeraCrypt 风格的加密算法基准测试。
 *
 * 用 [NativeBridge.openRandomFill] 为每种算法建一套临时 XTS 加密会话（独立随机主密钥，
 * 不依赖任何卷句柄），对 1 MiB 缓冲区反复加密计时，算出吞吐 MB/s。
 *
 * 调用方须在 IO 线程执行 [run]（内部为阻塞式 native 调用）。
 */
object BenchmarkRunner {

    /**
     * 受测算法列表：(EA ID, 显示名)。
     *
     * EA ID = native `EncryptionAlgorithms` 数组的 1-based 索引（见 cpp/veracrypt/Common/Crypto.c）。
     * 本项目 native 数组顺序为：单算法在前（AES=1…Kuznyechik=5），级联从 6 开始。
     */
    private val ALGORITHMS = listOf(
        1 to "AES-256",
        2 to "Serpent",
        3 to "Twofish",
        4 to "Camellia",
        5 to "Kuznyechik",
        6 to "Twofish-AES",
        7 to "Serpent-Twofish-AES",
        8 to "AES-Serpent",
        9 to "AES-Twofish-Serpent",
        10 to "Serpent-Twofish",
    )

    /** 每轮加密的 512B 单元数：2048 * 512 = 1 MiB。 */
    private const val BUF_UNITS = 2048

    /** 每种算法重复加密次数，取总时间算平均吞吐。 */
    private const val ROUNDS = 10

    /** 缓冲区大小（字节）= 1 MiB。 */
    private const val BUF_SIZE = BUF_UNITS * NativeBridge.UNIT_SIZE

    /**
     * 依次测全部算法。在 IO 线程调用。
     *
     * [onProgress] 在每种算法开始加密前回调其显示名，供 UI 展示当前进度。
     * 返回结果按速度降序排列。native 不可用返回空表。
     */
    fun run(onProgress: (String) -> Unit): List<BenchResult> {
        if (!NativeBridge.isAvailable) return emptyList()

        // openRandomFill 内部需从 native 随机池取临时主密钥 + XTS 副密钥，先灌足熵。
        seedEntropy(4096)

        val results = mutableListOf<BenchResult>()
        val buf = ByteArray(BUF_SIZE)

        for ((eaId, name) in ALGORITHMS) {
            onProgress(name)

            val fill = NativeBridge.openRandomFill(eaId)
            if (fill == null) {
                // 熵不足或算法不支持——记 0 分，不中断整批。
                results.add(BenchResult(eaId, name, 0.0))
                continue
            }

            fill.use { f ->
                val start = System.nanoTime()
                repeat(ROUNDS) { f.encryptZeroBlock(buf, 0L, BUF_UNITS) }
                val elapsedSec = (System.nanoTime() - start) / 1e9
                val totalMB = ROUNDS.toDouble() * BUF_SIZE / 1024.0 / 1024.0
                val speed = if (elapsedSec > 0) totalMB / elapsedSec else 0.0
                results.add(BenchResult(eaId, name, speed))
            }

            // 每种算法消耗一些熵（临时密钥），补充一次防止后续算法因熵不足失败。
            seedEntropy(2048)
        }

        return results.sortedByDescending { it.speedMBps }
    }

    /** 从 Android SecureRandom 取 [n] 字节灌入 native 随机池，灌后抹除本地副本。 */
    private fun seedEntropy(n: Int) {
        val entropy = ByteArray(n).also { SecureRandom().nextBytes(it) }
        NativeBridge.seedRandom(entropy)
        entropy.fill(0)
    }
}
