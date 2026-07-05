package com.henglie.sealchest.fs

/**
 * 空 FAT 文件系统镜像生成器（B2 创建容器用）。
 *
 * 只生成一个「格式化后、空的」FAT 文件系统的**关键扇区**（引导扇区 BPB + FAT 表首扇区
 * + FAT32 的 FSInfo/备份引导），不铺满整个数据区——空 FAT 的绝大部分扇区是全零，容器
 * 创建时数据区本就写成加密的全零，无需显式写出。
 *
 * 返回的 [FatImage.sectors] 是「卷内逻辑偏移 → 字节段」的稀疏列表，调用方（VolumeCreator）
 * 逐段经 VolumeReader.write 加密写入。逻辑偏移 0 = 数据区首字节 = FAT 引导扇区第一字节。
 *
 * FAT 类型按数据区大小自动选：< 512MB → FAT16，≥ 512MB → FAT32。FAT12 不做。
 *
 * 字节级参照 VeraCrypt Fat.c 的 GetFatParams + PutBoot（已确认编入 cpp/veracrypt），
 * 以及 Microsoft FAT 规范（fatgen103）。判据：桌面 VeraCrypt 挂载后 chkdsk 干净。
 */
object FatFormatter {

    /** 一个 FAT 文件系统镜像：bytesPerSector + 稀疏扇区列表（卷内逻辑偏移 → 内容）。 */
    data class FatImage(
        val bytesPerSector: Int,
        val sectors: List<Pair<Long, ByteArray>>,
    )

    private const val SECTOR = 512

    /** FAT16 / FAT32 分界：< 512MB 用 FAT16，否则 FAT32。 */
    private const val FAT32_THRESHOLD = 512L * 1024 * 1024

    /**
     * 为 [volumeSizeBytes] 大小的数据区生成空 FAT 镜像。
     *
     * @param volumeSizeBytes 数据区字节数（不含卷头组），512 对齐。
     * @return 稀疏 FAT 镜像；调用方按 sectors 逐段加密写入数据区。
     */
    fun buildEmptyFat(volumeSizeBytes: Long): FatImage {
        require(volumeSizeBytes % SECTOR == 0L) { "数据区须 512 对齐：$volumeSizeBytes" }
        val totalSectors = volumeSizeBytes / SECTOR
        require(totalSectors >= 64) { "数据区过小，放不下 FAT：$totalSectors 扇区" }

        return if (volumeSizeBytes < FAT32_THRESHOLD) {
            buildFat16(totalSectors)
        } else {
            buildFat32(totalSectors)
        }
    }

    // ================================================================
    //  FAT16
    // ================================================================
    private fun buildFat16(totalSectors: Long): FatImage {
        val sectors = mutableListOf<Pair<Long, ByteArray>>()

        val volumeSizeBytes = totalSectors * SECTOR
        // 簇大小：保证簇数落在 FAT16 合法区间（4085..65524）。经验阶梯。
        val sectorsPerCluster = when {
            volumeSizeBytes < 16L * 1024 * 1024 -> 4     // <16MB: 2KB 簇
            volumeSizeBytes < 128L * 1024 * 1024 -> 8    // <128MB: 4KB 簇
            else -> 16                                   // 8KB 簇
        }
        val reservedSectors = 1
        val numFats = 2
        val rootEntries = 512                            // FAT16 惯例 512 项
        val rootDirSectors = (rootEntries * 32 + SECTOR - 1) / SECTOR

        // 估算数据簇数，反推每份 FAT 扇区数（FAT16 每项 2 字节，含首 2 个保留项）。
        val dataSectorsApprox = totalSectors - reservedSectors - rootDirSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = (((clustersApprox + 2) * 2) + SECTOR - 1) / SECTOR

        // ---- 引导扇区（BPB）----
        val boot = ByteArray(SECTOR)
        writeBpbCommon(boot, sectorsPerCluster, reservedSectors, numFats, totalSectors)
        putShort(boot, 0x11, rootEntries)                // BPB_RootEntCnt
        putShort(boot, 0x16, fatSectors.toInt())         // BPB_FATSz16
        boot[0x15] = 0xF8.toByte()                       // 媒体类型（固定盘）
        // FAT16 扩展引导记录（0x24 起）
        boot[0x24] = 0x80.toByte()                       // BS_DrvNum
        boot[0x26] = 0x29                                // BS_BootSig
        writeFsType(boot, 0x36, "FAT16   ")              // BS_FilSysType
        boot[0x1FE] = 0x55                               // 引导扇区签名
        boot[0x1FF] = 0xAA.toByte()
        sectors.add(0L to boot)

        // ---- FAT 表首扇区：前 2 项为保留项 ----
        // FAT16: F8 FF（首项=媒体字节 0xFFF8） | FF FF（次项=EOC）
        val fat0 = ByteArray(SECTOR)
        fat0[0] = 0xF8.toByte(); fat0[1] = 0xFF.toByte()
        fat0[2] = 0xFF.toByte(); fat0[3] = 0xFF.toByte()
        val fat1Start = reservedSectors.toLong() * SECTOR
        val fat2Start = (reservedSectors + fatSectors) * SECTOR
        sectors.add(fat1Start to fat0)
        sectors.add(fat2Start to fat0.copyOf())

        return FatImage(SECTOR, sectors)
    }

    // ================================================================
    //  FAT32
    // ================================================================
    private fun buildFat32(totalSectors: Long): FatImage {
        val sectors = mutableListOf<Pair<Long, ByteArray>>()

        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = when {
            volumeSizeBytes < 8L * 1024 * 1024 * 1024 -> 8    // <8GB: 4KB 簇
            else -> 16                                        // 8KB 簇
        }
        val reservedSectors = 32                         // FAT32 惯例 32（含 FSInfo + 备份引导）
        val numFats = 2

        // FAT32 根目录是普通簇链，不占固定区；RootEntCnt=0。
        val dataSectorsApprox = totalSectors - reservedSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = (((clustersApprox + 2) * 4) + SECTOR - 1) / SECTOR   // FAT32 每项 4 字节

        // ---- 引导扇区（BPB）----
        val boot = ByteArray(SECTOR)
        writeBpbCommon(boot, sectorsPerCluster, reservedSectors, numFats, totalSectors)
        putShort(boot, 0x11, 0)                          // RootEntCnt=0（FAT32）
        putShort(boot, 0x16, 0)                          // FATSz16=0（改用 FATSz32）
        putInt(boot, 0x24, fatSectors.toInt())           // BPB_FATSz32
        putInt(boot, 0x2C, 2)                            // BPB_RootClus=2（根目录首簇）
        putShort(boot, 0x30, 1)                          // BPB_FSInfo=1
        putShort(boot, 0x32, 6)                          // BPB_BkBootSec=6
        boot[0x15] = 0xF8.toByte()                       // 媒体类型
        // FAT32 扩展引导记录（0x40 起）
        boot[0x40] = 0x80.toByte()                       // BS_DrvNum
        boot[0x42] = 0x29                                // BS_BootSig
        writeFsType(boot, 0x52, "FAT32   ")              // BS_FilSysType（FAT32 在 0x52）
        boot[0x1FE] = 0x55
        boot[0x1FF] = 0xAA.toByte()
        sectors.add(0L to boot)

        // ---- FSInfo 扇区（扇区 1）----
        val fsInfo = ByteArray(SECTOR)
        putInt(fsInfo, 0, 0x41615252)                    // FSI_LeadSig
        putInt(fsInfo, 484, 0x61417272)                  // FSI_StrucSig
        putInt(fsInfo, 488, -1)                          // FSI_Free_Count = 未知（OS 重算）
        putInt(fsInfo, 492, -1)                          // FSI_Nxt_Free = 未知
        putInt(fsInfo, 508, 0xAA550000.toInt())          // FSI_TrailSig
        sectors.add(1L * SECTOR to fsInfo)

        // ---- 备份引导扇区（扇区 6）----
        sectors.add(6L * SECTOR to boot.copyOf())

        // ---- FAT 表首扇区：FAT32 前 3 项 ----
        // 首项=媒体字节 0x0FFFFFF8 | 次项=EOC 0x0FFFFFFF | 簇2（根目录）=EOC 0x0FFFFFFF
        val fat0 = ByteArray(SECTOR)
        putInt(fat0, 0, 0x0FFFFFF8)
        putInt(fat0, 4, 0x0FFFFFFF)
        putInt(fat0, 8, 0x0FFFFFFF)
        val fat1Start = reservedSectors.toLong() * SECTOR
        val fat2Start = (reservedSectors + fatSectors) * SECTOR
        sectors.add(fat1Start to fat0)
        sectors.add(fat2Start to fat0.copyOf())

        // FAT32 根目录首簇（簇2）内容为全零 = 空目录，靠数据区加密全零覆盖，无需显式写。

        return FatImage(SECTOR, sectors)
    }

    // ================================================================
    //  BPB 公共字段（FAT16/32 共有的偏移 0x00..0x24 区）
    // ================================================================
    private fun writeBpbCommon(
        boot: ByteArray,
        sectorsPerCluster: Int,
        reservedSectors: Int,
        numFats: Int,
        totalSectors: Long,
    ) {
        // 0x00: 跳转指令 JMP（EB xx 90），VeraCrypt/规范惯例。
        boot[0] = 0xEB.toByte(); boot[1] = 0x58; boot[2] = 0x90.toByte()
        // 0x03: OEM 名 "MSDOS5.0"（解密判据依赖此，见 PROGRESS 踩坑）。
        writeFsType(boot, 0x03, "MSDOS5.0")
        putShort(boot, 0x0B, SECTOR)                     // BPB_BytsPerSec
        boot[0x0D] = sectorsPerCluster.toByte()          // BPB_SecPerClus
        putShort(boot, 0x0E, reservedSectors)            // BPB_RsvdSecCnt
        boot[0x10] = numFats.toByte()                    // BPB_NumFATs
        putShort(boot, 0x13, 0)                          // BPB_TotSec16=0（用 TotSec32）
        boot[0x15] = 0xF8.toByte()                       // BPB_Media
        putShort(boot, 0x18, 63)                         // BPB_SecPerTrk（惯例值）
        putShort(boot, 0x1A, 255)                        // BPB_NumHeads（惯例值）
        putInt(boot, 0x1C, 0)                            // BPB_HiddSec=0（文件容器无分区偏移）
        putInt(boot, 0x20, totalSectors.toInt())         // BPB_TotSec32
    }

    // ---- 小端写入辅助 ----
    private fun putShort(buf: ByteArray, off: Int, v: Int) {
        buf[off] = (v and 0xFF).toByte()
        buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
    }

    private fun putInt(buf: ByteArray, off: Int, v: Int) {
        buf[off] = (v and 0xFF).toByte()
        buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
        buf[off + 2] = ((v ushr 16) and 0xFF).toByte()
        buf[off + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    /** 写定长 ASCII 字段（不足补空格已由调用方在字符串里给足，多余截断）。 */
    private fun writeFsType(buf: ByteArray, off: Int, s: String) {
        val bytes = s.toByteArray(Charsets.US_ASCII)
        for (i in bytes.indices) buf[off + i] = bytes[i]
    }
}
