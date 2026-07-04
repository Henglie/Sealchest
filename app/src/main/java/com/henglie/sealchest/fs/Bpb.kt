package com.henglie.sealchest.fs

/**
 * BIOS Parameter Block（引导扇区前 512 字节）解析结果。
 *
 * FAT 类型判定唯一权威依据是「数据区簇总数」（微软规范）：
 *   < 4085        → FAT12
 *   < 65525       → FAT16
 *   否则          → FAT32
 * 不能靠文件系统类型串（"FAT32   "）判，那只是提示、不可信。
 */
class Bpb private constructor(
    val bytesPerSector: Int,
    val sectorsPerCluster: Int,
    val reservedSectors: Int,
    val numFats: Int,
    val rootEntryCount: Int,
    val fatSizeSectors: Int,
    val totalSectors: Long,
    val rootCluster: Long,        // FAT32 专有；FAT12/16 为 0
    val countOfClusters: Int,
    val fatType: FatFileSystem.FatType,
    val volumeLabel: String,
    /** FAT32 FSInfo 扇区号（BPB 偏移 48，u16）；FAT12/16 或无 FSInfo 为 0。 */
    val fsInfoSector: Int,
) {
    companion object {
        fun parse(boot: ByteArray): Bpb {
            require(boot.size >= 512) { "引导扇区不足 512 字节" }
            // 起手跳转指令：EB xx 90 或 E9。不满足基本不是 FAT 引导扇区。
            val b0 = boot[0].toInt() and 0xFF
            require(b0 == 0xEB || b0 == 0xE9) { "非 FAT 引导扇区（跳转指令不符）" }
            // 末尾签名 0x55AA。
            require((boot[510].toInt() and 0xFF) == 0x55 && (boot[511].toInt() and 0xFF) == 0xAA) {
                "引导扇区签名不是 0x55AA"
            }

            fun u16(off: Int) = (boot[off].toInt() and 0xFF) or ((boot[off + 1].toInt() and 0xFF) shl 8)
            fun u32(off: Int) = ((boot[off].toInt() and 0xFF).toLong()) or
                ((boot[off + 1].toInt() and 0xFF).toLong() shl 8) or
                ((boot[off + 2].toInt() and 0xFF).toLong() shl 16) or
                ((boot[off + 3].toInt() and 0xFF).toLong() shl 24)

            val bytesPerSector = u16(11)
            require(bytesPerSector in intArrayOf(512, 1024, 2048, 4096)) {
                "异常 bytesPerSector=$bytesPerSector"
            }
            val sectorsPerCluster = boot[13].toInt() and 0xFF
            require(sectorsPerCluster > 0 && (sectorsPerCluster and (sectorsPerCluster - 1)) == 0) {
                "sectorsPerCluster 非 2 的幂：$sectorsPerCluster"
            }
            val reservedSectors = u16(14)
            val numFats = boot[16].toInt() and 0xFF
            val rootEntryCount = u16(17)
            val totalSectors16 = u16(19)
            val fatSize16 = u16(22)
            val totalSectors32 = u32(32)
            val fatSize32 = u32(36)

            val fatSizeSectors = if (fatSize16 != 0) fatSize16 else fatSize32.toInt()
            val totalSectors = if (totalSectors16 != 0) totalSectors16.toLong() else totalSectors32

            // 数据区簇数推导（微软规范原式）。
            val rootDirSectors = ((rootEntryCount * 32) + (bytesPerSector - 1)) / bytesPerSector
            val dataSectors = totalSectors -
                (reservedSectors + numFats.toLong() * fatSizeSectors + rootDirSectors)
            val countOfClusters = (dataSectors / sectorsPerCluster).toInt()

            val fatType = when {
                countOfClusters < 4085 -> FatFileSystem.FatType.FAT12
                countOfClusters < 65525 -> FatFileSystem.FatType.FAT16
                else -> FatFileSystem.FatType.FAT32
            }

            val rootCluster = if (fatType == FatFileSystem.FatType.FAT32) u32(44) else 0L
            // FSInfo 扇区号在 FAT32 BPB 偏移 48（u16）。0 或 0xFFFF 视为无。
            val fsInfoSector = if (fatType == FatFileSystem.FatType.FAT32) {
                val s = u16(48)
                if (s == 0 || s == 0xFFFF) 0 else s
            } else 0

            // 卷标：FAT12/16 在 0x2B（11 字节），FAT32 在 0x47。
            val labelOff = if (fatType == FatFileSystem.FatType.FAT32) 0x47 else 0x2B
            val label = buildString {
                for (k in 0 until 11) {
                    val c = boot[labelOff + k].toInt() and 0xFF
                    append(c.toChar())
                }
            }.trimEnd()

            return Bpb(
                bytesPerSector, sectorsPerCluster, reservedSectors, numFats,
                rootEntryCount, fatSizeSectors, totalSectors, rootCluster,
                countOfClusters, fatType, label, fsInfoSector,
            )
        }
    }
}
