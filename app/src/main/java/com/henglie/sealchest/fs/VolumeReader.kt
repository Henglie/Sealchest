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

    override fun close() {
        cache.clear()
        volume.close()
    }
}
