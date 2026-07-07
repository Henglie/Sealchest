package com.henglie.sealchest.fs

/**
 * NTFS 引导扇区（$Boot / VBR 前 512B）解析结果。
 *
 * NTFS 判定权威依据：偏移 3 起 8 字节 OEM ID = "NTFS    "（四尾空格）。
 * 关键布局字段（小端）：
 *   0x0B  u16  BytesPerSector
 *   0x0D  u8   SectorsPerCluster
 *   0x28  u64  TotalSectors
 *   0x30  u64  MftClusterNumber（$MFT 起始簇号）
 *   0x38  u64  MftMirrClusterNumber
 *   0x40  i8   ClustersPerFileRecordSegment（正=簇数；负=2^(-v) 字节）
 *   0x44  i8   ClustersPerIndexBuffer（同上语义）
 *
 * 所有簇号换算成卷内逻辑字节偏移（[VolumeReader] 直接吃）。
 * 规范：NTFS on-disk layout（Linux-NTFS / ntfs-3g 文档）。
 */
class NtfsBoot private constructor(
    val bytesPerSector: Int,
    val sectorsPerCluster: Int,
    val bytesPerCluster: Int,
    val totalSectors: Long,
    /** $MFT 起始簇号。 */
    val mftCluster: Long,
    /** MFT 文件记录字节大小（通常 1024）。 */
    val fileRecordSize: Int,
    /** 索引缓冲字节大小（通常 4096）。 */
    val indexRecordSize: Int,
) {
    /** 簇号 → 卷内逻辑字节偏移。NTFS 簇从 0 起（与 FAT 不同）。 */
    fun clusterToOffset(cluster: Long): Long = cluster * bytesPerCluster

    /** $MFT 起始逻辑字节偏移。 */
    val mftByteOffset: Long get() = mftCluster * bytesPerCluster

    companion object {
        /** NTFS OEM 签名（偏移 3，8 字节）。 */
        val SIGNATURE = byteArrayOf(
            'N'.code.toByte(), 'T'.code.toByte(), 'F'.code.toByte(), 'S'.code.toByte(),
            ' '.code.toByte(), ' '.code.toByte(), ' '.code.toByte(), ' '.code.toByte(),
        )

        /** 引导扇区（512B）是否 NTFS：偏移 3 起匹配 "NTFS    "。 */
        fun isNtfs(boot: ByteArray): Boolean {
            if (boot.size < 512) return false
            for (k in 0 until 8) if (boot[3 + k] != SIGNATURE[k]) return false
            return true
        }

        /**
         * 由 ClustersPerXxx 字段（i8）算记录字节大小：
         *   正值 → 簇数 × 每簇字节；负值 → 2^(-value) 字节（记录小于一簇时）。
         */
        private fun recordSize(raw: Int, bytesPerCluster: Int): Int {
            val v = raw.toByte().toInt()   // 有符号
            return if (v >= 0) v * bytesPerCluster else 1 shl (-v)
        }

        fun parse(boot: ByteArray): NtfsBoot {
            require(boot.size >= 512) { "引导扇区不足 512 字节" }
            require(isNtfs(boot)) { "非 NTFS 引导扇区（NTFS 签名不符）" }

            fun u16(off: Int) = (boot[off].toInt() and 0xFF) or ((boot[off + 1].toInt() and 0xFF) shl 8)
            fun u64(off: Int): Long {
                var v = 0L
                for (k in 0 until 8) v = v or ((boot[off + k].toInt() and 0xFF).toLong() shl (8 * k))
                return v
            }

            val bytesPerSector = u16(0x0B)
            require(bytesPerSector in intArrayOf(256, 512, 1024, 2048, 4096)) {
                "异常 bytesPerSector=$bytesPerSector"
            }
            val sectorsPerCluster = boot[0x0D].toInt() and 0xFF
            require(sectorsPerCluster > 0) { "异常 sectorsPerCluster=$sectorsPerCluster" }
            val bytesPerCluster = bytesPerSector * sectorsPerCluster

            val totalSectors = u64(0x28)
            val mftCluster = u64(0x30)
            require(mftCluster > 0) { "异常 MFT 簇号=$mftCluster" }

            val fileRecordSize = recordSize(boot[0x40].toInt() and 0xFF, bytesPerCluster)
            val indexRecordSize = recordSize(boot[0x44].toInt() and 0xFF, bytesPerCluster)
            require(fileRecordSize >= 512) { "异常文件记录大小=$fileRecordSize" }

            return NtfsBoot(
                bytesPerSector = bytesPerSector,
                sectorsPerCluster = sectorsPerCluster,
                bytesPerCluster = bytesPerCluster,
                totalSectors = totalSectors,
                mftCluster = mftCluster,
                fileRecordSize = fileRecordSize,
                indexRecordSize = indexRecordSize,
            )
        }
    }
}
