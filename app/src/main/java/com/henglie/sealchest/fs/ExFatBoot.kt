package com.henglie.sealchest.fs

/**
 * exFAT 引导扇区（VBR，Main Boot Sector）解析结果。
 *
 * exFAT 判定唯一权威依据：引导扇区偏移 3 起 8 字节 = "EXFAT   "（三尾空格补齐）。
 * 与 FAT 的 BPB 完全不同——exFAT 不用 BPB，字段布局固定在偏移 64 起。
 * 所有区偏移以「扇区」计，本类换算成卷内逻辑字节偏移（[VolumeReader] 直接吃）。
 *
 * 规范：Microsoft exFAT file system specification（2019）。
 */
class ExFatBoot private constructor(
    val bytesPerSector: Int,
    val sectorsPerCluster: Int,
    val bytesPerCluster: Int,
    /** FAT 区逻辑字节偏移。 */
    val fatByteOffset: Long,
    /** FAT 区字节长度。 */
    val fatByteLength: Long,
    /** 簇堆逻辑字节偏移（簇 2 的位置）。 */
    val clusterHeapByteOffset: Long,
    /** 簇总数（不含保留的 0/1）。 */
    val clusterCount: Long,
    /** 根目录首簇。 */
    val rootCluster: Long,
    /** 卷标（从根目录 0x83 项读，引导扇区不含；解析后回填，默认空）。 */
    var volumeLabel: String,
    val numFats: Int,
) {
    /** 簇号 → 卷内逻辑字节偏移。簇编号从 2 起。 */
    fun clusterToOffset(cluster: Long): Long =
        clusterHeapByteOffset + (cluster - 2) * bytesPerCluster

    companion object {
        /** exFAT 文件系统名签名（偏移 3，8 字节）。 */
        val SIGNATURE = byteArrayOf(
            'E'.code.toByte(), 'X'.code.toByte(), 'F'.code.toByte(), 'A'.code.toByte(),
            'T'.code.toByte(), ' '.code.toByte(), ' '.code.toByte(), ' '.code.toByte(),
        )

        /** 引导扇区（512B）是否 exFAT：偏移 3 起匹配 "EXFAT   "。 */
        fun isExFat(boot: ByteArray): Boolean {
            if (boot.size < 512) return false
            for (k in 0 until 8) if (boot[3 + k] != SIGNATURE[k]) return false
            return true
        }

        fun parse(boot: ByteArray): ExFatBoot {
            require(boot.size >= 512) { "引导扇区不足 512 字节" }
            require(isExFat(boot)) { "非 exFAT 引导扇区（EXFAT 签名不符）" }
            require((boot[510].toInt() and 0xFF) == 0x55 && (boot[511].toInt() and 0xFF) == 0xAA) {
                "引导扇区签名不是 0x55AA"
            }

            fun u32(off: Int) = ((boot[off].toInt() and 0xFF).toLong()) or
                ((boot[off + 1].toInt() and 0xFF).toLong() shl 8) or
                ((boot[off + 2].toInt() and 0xFF).toLong() shl 16) or
                ((boot[off + 3].toInt() and 0xFF).toLong() shl 24)

            val fatOffsetSec = u32(80)
            val fatLengthSec = u32(84)
            val clusterHeapOffsetSec = u32(88)
            val clusterCount = u32(92)
            val rootCluster = u32(96)
            val bytesPerSectorShift = boot[108].toInt() and 0xFF
            val sectorsPerClusterShift = boot[109].toInt() and 0xFF
            val numFats = boot[110].toInt() and 0xFF

            require(bytesPerSectorShift in 9..12) { "异常 BytesPerSectorShift=$bytesPerSectorShift" }
            require(sectorsPerClusterShift in 0..25) { "异常 SectorsPerClusterShift=$sectorsPerClusterShift" }
            require(numFats in 1..2) { "异常 NumberOfFats=$numFats" }
            require(rootCluster >= 2) { "异常 RootCluster=$rootCluster" }

            val bytesPerSector = 1 shl bytesPerSectorShift
            val sectorsPerCluster = 1 shl sectorsPerClusterShift
            val bytesPerCluster = bytesPerSector * sectorsPerCluster

            return ExFatBoot(
                bytesPerSector = bytesPerSector,
                sectorsPerCluster = sectorsPerCluster,
                bytesPerCluster = bytesPerCluster,
                fatByteOffset = fatOffsetSec * bytesPerSector,
                fatByteLength = fatLengthSec * bytesPerSector,
                clusterHeapByteOffset = clusterHeapOffsetSec * bytesPerSector,
                clusterCount = clusterCount,
                rootCluster = rootCluster,
                volumeLabel = "",
                numFats = numFats,
            )
        }
    }
}
