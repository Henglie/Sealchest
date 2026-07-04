package com.henglie.sealchest.fs

import com.henglie.sealchest.crypto.NativeBridge
import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * 解密读取层：把「卷内逻辑偏移」翻译成「容器文件绝对单元号」再解密。
 *
 * 逻辑偏移 0 = 卷数据区首字节（= 解密后 FAT 引导扇区）。FAT 层只见逻辑偏移，
 * 不碰加密细节。偏移语义（真容器实测坐实，见 PROGRESS 踩坑）：
 *   文件绝对偏移 = [encStart] + 逻辑偏移
 *   XTS 单元号   = 文件绝对偏移 / [UNIT]
 * 即数据区首扇区的单元号是 [encStart]/512（512KB 测试容器为 256），不是 0。
 *
 * 带一个 512B 解密单元的 LRU 缓存：FAT 表和目录会被反复随机访问，缓存命中省去
 * 重复的密文读 + XTS 解密。线程不安全（VeraCrypt 核心单线程），调用方串行化。
 *
 * [channel] 覆盖容器密文（SAF PFD 的 FileChannel），[volume] 是已开卷句柄。
 * [close] 只关卷（销毁密钥），不负责关 channel / PFD —— 那归 [MountManager]。
 */
class VolumeReader(
    private val channel: FileChannel,
    private val volume: NativeBridge.Volume,
) : Closeable {

    private val encStart: Long = volume.encryptedAreaStart

    /** 卷数据区字节数（不含头），逻辑偏移上界。 */
    val dataSize: Long = volume.volumeSize

    private companion object {
        const val UNIT = 512
        /** 512B * 512 = 256KB 解密缓存，够覆盖 FAT 表热点。 */
        const val CACHE_UNITS = 512
    }

    /** 访问序 LRU：最近用过的解密单元留下，最旧的淘汰。 */
    private val cache = object : LinkedHashMap<Long, ByteArray>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, ByteArray>?): Boolean =
            size > CACHE_UNITS
    }

    /** 取（并缓存）绝对单元号 [unitNo] 的解密后 512 字节。越过文件尾则补零。 */
    private fun decryptUnit(unitNo: Long): ByteArray {
        cache[unitNo]?.let { return it }
        val buf = ByteArray(UNIT)
        val bb = ByteBuffer.wrap(buf)
        var pos = unitNo * UNIT
        while (bb.hasRemaining()) {
            val n = channel.read(bb, pos)
            if (n < 0) break          // EOF：剩余保持 0
            pos += n
        }
        volume.decryptUnits(unitNo, buf, 1)
        cache[unitNo] = buf
        return buf
    }

    /**
     * 读卷内 [logicalOffset] 起 [length] 字节（解密后），返回新数组。
     * 跨单元自动拼接；越过 [dataSize] 的部分为 0。
     */
    fun read(logicalOffset: Long, length: Int): ByteArray {
        val out = ByteArray(length)
        read(logicalOffset, out, 0, length)
        return out
    }

    /**
     * 读卷内 [logicalOffset] 起 [length] 字节到 [dst] 的 [dstOff] 处。
     * 返回实际写入字节数（正常 = [length]）。
     */
    fun read(logicalOffset: Long, dst: ByteArray, dstOff: Int, length: Int): Int {
        var written = 0
        var lo = logicalOffset
        while (written < length) {
            val fileOff = encStart + lo
            val unitNo = fileOff / UNIT
            val within = (fileOff - unitNo * UNIT).toInt()
            val chunk = minOf(UNIT - within, length - written)
            val sec = decryptUnit(unitNo)
            System.arraycopy(sec, within, dst, dstOff + written, chunk)
            written += chunk
            lo += chunk
        }
        return written
    }

    /**
     * 写卷内 [logicalOffset] 起 [length] 字节（取自 [src] 的 [srcOff]）。
     *
     * 按 512B 单元 read-modify-write：不整对齐的单元先解密出原明文，覆盖要写的
     * 部分，再整单元加密写回 channel。缓存里的明文副本同步更新，保证后续读一致。
     *
     * 写入后必须 [flush] 才落盘（channel.force）。上层（FAT 写）在一批结构改动
     * 完成后统一 flush，减少半写状态。仍是崩溃不原子 —— 二期考虑日志/双写头。
     */
    fun write(logicalOffset: Long, src: ByteArray, srcOff: Int, length: Int) {
        var done = 0
        var lo = logicalOffset
        while (done < length) {
            val fileOff = encStart + lo
            val unitNo = fileOff / UNIT
            val within = (fileOff - unitNo * UNIT).toInt()
            val chunk = minOf(UNIT - within, length - done)

            // 取该单元当前明文（缓存或解密）。整单元覆盖时也要有基底，避免读残留。
            val plain = decryptUnit(unitNo)
            System.arraycopy(src, srcOff + done, plain, within, chunk)

            // 加密副本写回：不能加密缓存本身（缓存存明文），拷出来加密。
            val cipher = plain.copyOf()
            volume.encryptUnits(unitNo, cipher, 1)
            val bb = ByteBuffer.wrap(cipher)
            var pos = unitNo * UNIT
            while (bb.hasRemaining()) {
                val n = channel.write(bb, pos)
                if (n < 0) break
                pos += n
            }
            // 缓存持有的仍是最新明文（plain 已就地更新），无需动。
            done += chunk
            lo += chunk
        }
    }

    /** 便捷：整段写。 */
    fun write(logicalOffset: Long, src: ByteArray) = write(logicalOffset, src, 0, src.size)

    /**
     * 加解密往返自测（写入互通的地基，零风险，全程内存操作、绝不写盘）。
     *
     * 与 cpp/sc_test.c 的往返自测同一套判据，搬进 App 用真机 + 真容器验（比 x86_64
     * 模拟器更接近最终 arm64 ABI）。取数据区首单元的真实密文，验三件事：
     *   1. [encReproduces] 往返1：decrypt(C0)=P0 后 encrypt(P0) 必须复现原密文 C0
     *      —— 证明 encrypt 方向与 decrypt 用同一密钥 / 同一 XTS 单元号语义。这是
     *      写回容器后桌面 VeraCrypt 还能打开的充要条件。
     *   2. [encChanges] 加密确实改变数据（排除 encrypt 空转）。
     *   3. [roundtripLossless] 往返2：造明文 X，encrypt→decrypt 必须无损还原 X。
     * 三者全真才 [SelfTestResult.passed]。任一假 → encrypt 方向有 bug，不许往下做写入。
     *
     * 只在局部数组上加解密，channel 只读一个扇区、绝不写，故对挂载中的卷完全无副作用。
     */
    fun selfTest(): SelfTestResult {
        val unitNo = encStart / UNIT
        val pos = unitNo * UNIT

        // 读数据区首单元的真实密文 C0（直接读 channel，不经缓存、不解密）。
        val c0 = ByteArray(UNIT)
        run {
            val bb = ByteBuffer.wrap(c0)
            var p = pos
            while (bb.hasRemaining()) {
                val n = channel.read(bb, p)
                if (n < 0) break
                p += n
            }
        }

        // 往返1：decrypt(C0)=P0，再 encrypt(P0) 应复现 C0。
        val p0 = c0.copyOf()
        volume.decryptUnits(unitNo, p0, 1)
        val encChanges = !p0.contentEquals(c0)
        val recc = p0.copyOf()
        volume.encryptUnits(unitNo, recc, 1)
        val encReproduces = recc.contentEquals(c0)

        // 往返2：造可辨识明文 X，encrypt 后 decrypt 必须还原 X。
        val x = ByteArray(UNIT) { (it and 0xFF).toByte() }
        val y = x.copyOf()
        volume.encryptUnits(unitNo, y, 1)
        volume.decryptUnits(unitNo, y, 1)
        val roundtripLossless = y.contentEquals(x)

        return SelfTestResult(encReproduces, encChanges, roundtripLossless)
    }

    /** [selfTest] 三判据结果。[passed] 全真才算 encrypt 方向可用于写入。 */
    data class SelfTestResult(
        val encReproduces: Boolean,
        val encChanges: Boolean,
        val roundtripLossless: Boolean,
    ) {
        val passed: Boolean get() = encReproduces && encChanges && roundtripLossless
    }

    /** 落盘。FAT 写在一批结构改动后调用。 */
    fun flush() {
        runCatching { channel.force(false) }
    }

    override fun close() {
        cache.clear()
        volume.close()
    }
}
