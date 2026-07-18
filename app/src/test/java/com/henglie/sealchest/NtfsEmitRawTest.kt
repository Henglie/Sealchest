package com.henglie.sealchest

import com.henglie.sealchest.fs.NtfsFormatter
import org.junit.Test
import java.io.File

/**
 * 把 NtfsFormatter.buildEmpty 的**纯 App 原始字节**（未经 Windows 挂载改写、未经 VeraCrypt）
 * 落盘到 C:\Temp\ntfs_raw_<cs>.bin，供 VHD format+overwrite chkdsk 验证使用。
 *
 * 这是地面真相：dump 挂载后的容器会被 Windows repair-on-mount 改写（MFT#5 冒 $TXF_DATA），
 * 且 read_sectors 不做 USA fixup（realSize 高位混入 USN），都不可信。本测试直出原始镜像。
 *
 * 用 -Dntfs.emit.dir 指定输出目录（默认 C:\Temp）。
 */
class NtfsEmitRawTest {

    private val dataSize = 10L * 1024 * 1024
    private val clusterMatrix = listOf(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 0)
    private fun tag(cs: Int) = if (cs == 0) "auto" else when (cs) {
        512 -> "512b"; 1024 -> "1k"; 2048 -> "2k"; 4096 -> "4k"
        8192 -> "8k"; 16384 -> "16k"; 32768 -> "32k"; 65536 -> "64k"; else -> cs.toString()
    }

    @Test
    fun emitRawBins() {
        val dir = System.getProperty("ntfs.emit.dir") ?: "C:\\Temp"
        File(dir).mkdirs()
        for (cs in clusterMatrix) {
            val img = NtfsFormatter.buildEmpty(dataSize, cs)
            val image = ByteArray(dataSize.toInt())
            for ((off, bytes) in img.sectors) {
                System.arraycopy(bytes, 0, image, off.toInt(), bytes.size)
            }
            val f = File(dir, "ntfs_raw_${tag(cs)}.bin")
            f.writeBytes(image)
            println("EMIT ${f.absolutePath} size=${image.size}")
        }
    }
}
