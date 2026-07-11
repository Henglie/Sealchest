package com.henglie.sealchest.fs

/**
 * 空 NTFS 文件系统镜像生成器（三期 NTFS 创建后端，fsType=2）。
 *
 * VeraCrypt 桌面版对 NTFS 是挂盘符后调 Windows FormatEx/format.com（Format.c:802-853），
 * 其源码无 NTFS 造盘逻辑。安卓无等价设施 → 从零按 MS NTFS 规范 + ntfs-3g 公开实现自研。
 *
 * 产出复用 [FatFormatter.FatImage] 稀疏格式，由 [VolumeCreator] 逐段经 XTS 加密写入数据区。
 * 逻辑偏移 0 = 数据区首字节 = 引导扇区第一字节。NTFS 簇从 0 起（与 FAT 不同）。
 *
 * 空盘布局（4KB 簇 / 512B 扇区）：
 *   LCN 0..1        $Boot 引导区（8KB，扇区 0 = VBR + BPB）
 *   LCN mftLcn..    $MFT（32 条记录 × 1024B = 32KB）
 *   LCN logFileLcn  $LogFile（全 0xFF，Windows/chkdsk 当空日志接受）
 *   LCN bitmapLcn   $Bitmap（卷簇分配位图）
 *   LCN upcaseLcn   $UpCase（128KB 大写表）
 *   LCN attrDefLcn  $AttrDef（2560B 属性定义表，16 条 × 160B）
 *   LCN mftMirrLcn  $MFTMirr（前 4 条记录镜像，放卷中部）
 *
 * $MFT 含 12 条元数据记录（0..11）：$MFT/$MFTMirr/$LogFile/$Volume/$AttrDef/根目录/
 * $Bitmap/$Boot/$BadClus/$Secure/$UpCase/$Extend；记录 12..31 全零未分配。
 *
 * 诚实边界（同 [NtfsFileSystem] 写路径）：不写 $LogFile 日志，写完卷 Windows 当未净卸载、
 * 挂载时自动重置 $LogFile + chkdsk 补一致性。预期真机 chkdsk 报错迭代 2-3 轮才干净
 * （恒烈已知悉，要求达成而非警告）。判据：app 建 NTFS 容器 → 桌面 VC 挂载 + Windows 读写 + chkdsk 干净。
 *
 * 本文件只含主入口与引导区；MFT 记录构造见 [NtfsRecords]，底层工具见 [NtfsTables]。
 */
object NtfsFormatter {

    internal const val SECTOR = 512
    internal const val MFT_RECORD_SIZE = 1024
    internal const val INDEX_RECORD_SIZE = 4096
    internal const val UPCASE_SIZE = 131072          // 128KB
    internal const val ATTRDEF_SIZE = 2560           // 16 条 × 160B
    internal const val BOOT_SIZE = 8192              // 引导区 8KB（16 扇区）
    internal const val MIN_NTFS_SIZE = 8L * 1024 * 1024
    internal const val MFT_INITIAL_RECORDS = 32
    internal const val MFT_MIRR_RECORDS = 4

    internal const val ATTR_STANDARD_INFO = 0x10L
    internal const val ATTR_FILE_NAME = 0x30L
    internal const val ATTR_VOLUME_NAME = 0x60L
    internal const val ATTR_VOLUME_INFO = 0x70L
    internal const val ATTR_DATA = 0x80L
    internal const val ATTR_INDEX_ROOT = 0x90L
    internal const val ATTR_BITMAP = 0xB0L
    internal const val ATTR_END = 0xFFFFFFFFL

    internal const val FLAG_IN_USE = 0x0001
    internal const val FLAG_DIRECTORY = 0x0002

    /**
     * H4：把 [INDEX_RECORD_SIZE]（固定 4096）按 [bytesPerCluster] 编成 NTFS
     * ClustersPerIndexBuffer 字节（boot[0x44] 与 $INDEX_ROOT+0x0C 同一编码，见 NtfsBoot.recordSize）：
     *   簇 ≤ 4096 → 正数簇计（4096/簇：512→8、1024→4、2048→2、4096→1）；
     *   簇 > 4096 → 负数字节计（-log2(4096) = -12 → 0xF4）。
     * 原实现写死 1，只有默认 4KB 簇自洽，非默认簇下与 BPB 声明冲突、目录解析崩、chkdsk 报索引大小不符。
     */
    internal fun indexBufferCode(bytesPerCluster: Int): Int =
        if (INDEX_RECORD_SIZE >= bytesPerCluster) INDEX_RECORD_SIZE / bytesPerCluster
        else -(Integer.numberOfTrailingZeros(INDEX_RECORD_SIZE))
    internal const val FILE_ATTR_SYSTEM = 0x06L          // HIDDEN|SYSTEM
    internal const val FILE_ATTR_DIR_SYSTEM = 0x16L      // DIR|HIDDEN|SYSTEM
    internal const val NS_WIN32_AND_DOS = 3
    internal const val INDEX_ENTRY_LAST = 0x02

    /**
     * 为 [volumeSizeBytes] 大小的数据区生成空 NTFS 镜像。
     *
     * @param volumeSizeBytes 数据区字节数（不含卷头组），512 对齐，≥ 8MB。
     * @param clusterSizeOverride 大于 0 时强制簇字节大小（512 倍数），否则默认 4KB。
     * @param volumeLabel 卷标（UTF-16LE，最多 32 字符），空串则 $VOLUME_NAME 长度 0。
     */
    fun buildEmpty(
        volumeSizeBytes: Long,
        clusterSizeOverride: Int = 0,
        volumeLabel: String = "",
    ): FatFormatter.FatImage {
        require(volumeSizeBytes % SECTOR == 0L) { "数据区须 512 对齐：$volumeSizeBytes" }
        require(volumeSizeBytes >= MIN_NTFS_SIZE) {
            "NTFS 数据区过小：$volumeSizeBytes < 最小 $MIN_NTFS_SIZE（8MB）"
        }

        val bytesPerCluster = if (clusterSizeOverride > 0) {
            require(clusterSizeOverride % SECTOR == 0) { "簇大小须 512 倍数：$clusterSizeOverride" }
            clusterSizeOverride
        } else 4096
        val sectorsPerCluster = bytesPerCluster / SECTOR
        val totalSectors = volumeSizeBytes / SECTOR
        val totalClusters = totalSectors / sectorsPerCluster

        val bootClusters = BOOT_SIZE.toLong() / bytesPerCluster
        val bootLcn = 0L
        val mftBytes = MFT_INITIAL_RECORDS.toLong() * MFT_RECORD_SIZE
        val mftClusters = mftBytes / bytesPerCluster
        require(mftClusters * bytesPerCluster == mftBytes) { "MFT 大小非簇对齐：$mftBytes" }
        val mftLcn = bootLcn + bootClusters

        val logFileBytes = maxOf(512L * 1024, minOf(4L * 1024 * 1024, volumeSizeBytes / 4))
        val logFileClusters = (logFileBytes + bytesPerCluster - 1) / bytesPerCluster
        val logFileLcn = mftLcn + mftClusters

        val bitmapBytes = (totalClusters + 7) / 8
        val bitmapClusters = (bitmapBytes + bytesPerCluster - 1) / bytesPerCluster
        val bitmapLcn = logFileLcn + logFileClusters

        val upcaseClusters = UPCASE_SIZE.toLong() / bytesPerCluster
        val upcaseLcn = bitmapLcn + bitmapClusters

        val attrDefClusters = (ATTRDEF_SIZE.toLong() + bytesPerCluster - 1) / bytesPerCluster
        val attrDefLcn = upcaseLcn + upcaseClusters

        // H2：MFT 记录分配位图（$MFT 的 $BITMAP 0xB0）专用簇。totalMftRecords = MFT $DATA 字节 / 记录大小。
        //   位图 ceil(records/8) 字节，一簇足够（32 记录仅 4 字节）；nonResident 须整簇。
        val totalMftRecords = (mftClusters * bytesPerCluster) / MFT_RECORD_SIZE
        val mftBitmapRealSize = (totalMftRecords + 7) / 8
        val mftBitmapClusters = (mftBitmapRealSize + bytesPerCluster - 1) / bytesPerCluster
        val mftBitmapLcn = attrDefLcn + attrDefClusters
        val lastMetaLcn = mftBitmapLcn + mftBitmapClusters - 1

        val mftMirrBytes = MFT_MIRR_RECORDS.toLong() * MFT_RECORD_SIZE
        val mftMirrClusters = (mftMirrBytes + bytesPerCluster - 1) / bytesPerCluster
        var mftMirrLcn = totalClusters / 2
        if (mftMirrLcn <= lastMetaLcn || mftMirrLcn + mftMirrClusters > totalClusters) {
            mftMirrLcn = lastMetaLcn + 1
        }
        require(mftMirrLcn + mftMirrClusters <= totalClusters) {
            "NTFS 元数据放不下：mftMirrLcn=$mftMirrLcn totalClusters=$totalClusters"
        }
        require(lastMetaLcn < totalClusters) { "NTFS 元数据越界：lastMetaLcn=$lastMetaLcn" }

        val usedLcns = listOf(
            bootLcn to bootClusters, mftLcn to mftClusters, logFileLcn to logFileClusters,
            bitmapLcn to bitmapClusters, upcaseLcn to upcaseClusters,
            attrDefLcn to attrDefClusters, mftBitmapLcn to mftBitmapClusters,
            mftMirrLcn to mftMirrClusters,
        )

        val serial = randomSerial()
        val now = msToNtfsTime(System.currentTimeMillis())
        val rootRef = mftRef(5L)

        val sectors = ArrayList<Pair<Long, ByteArray>>()

        sectors.add(0L to buildBootRegion(sectorsPerCluster, totalSectors, mftLcn, mftMirrLcn, serial))

        val mftRecords = Array(MFT_INITIAL_RECORDS) { ByteArray(MFT_RECORD_SIZE) }
        mftRecords[0] = buildMftRecord(
            mftLcn, mftClusters, bytesPerCluster, now,
            mftBitmapLcn, mftBitmapClusters, mftBitmapRealSize,
        )
        mftRecords[1] = buildMftMirrRecord(mftMirrLcn, mftMirrClusters, bytesPerCluster, now, rootRef)
        mftRecords[2] = buildLogFileRecord(logFileLcn, logFileClusters, bytesPerCluster, now, rootRef)
        mftRecords[3] = buildVolumeRecord(volumeLabel, now, rootRef)
        mftRecords[4] = buildAttrDefRecord(attrDefLcn, attrDefClusters, bytesPerCluster, now, rootRef)
        mftRecords[5] = buildRootDirRecord(now, rootRef, bytesPerCluster)
        mftRecords[6] = buildBitmapRecord(bitmapLcn, bitmapClusters, bytesPerCluster, bitmapBytes, now, rootRef)
        mftRecords[7] = buildBootFileRecord(bootLcn, bootClusters, bytesPerCluster, now, rootRef)
        mftRecords[8] = buildBadClusRecord(totalClusters, bytesPerCluster, volumeSizeBytes, now, rootRef)
        mftRecords[9] = buildSecureRecord(now, rootRef)
        mftRecords[10] = buildUpcaseFileRecord(upcaseLcn, upcaseClusters, bytesPerCluster, now, rootRef)
        mftRecords[11] = buildExtendRecord(now, rootRef, bytesPerCluster)

        val mftImage = ByteArray((mftClusters * bytesPerCluster).toInt())
        for (i in 0 until MFT_INITIAL_RECORDS) {
            System.arraycopy(mftRecords[i], 0, mftImage, i * MFT_RECORD_SIZE, MFT_RECORD_SIZE)
        }
        sectors.add(mftLcn * bytesPerCluster to mftImage)

        val mirrImage = ByteArray((mftMirrClusters * bytesPerCluster).toInt())
        for (i in 0 until MFT_MIRR_RECORDS) {
            System.arraycopy(mftRecords[i], 0, mirrImage, i * MFT_RECORD_SIZE, MFT_RECORD_SIZE)
        }
        sectors.add(mftMirrLcn * bytesPerCluster to mirrImage)

        // $LogFile 填 0xFF（ntfs-3g mkfs 做法）：无有效 RSTR restart page → Windows/chkdsk
        //   识别为「空日志」并接受，挂载时靠 $Volume dirty 位触发 chkdsk 重建日志。
        //   原 ByteArray(...) 默认全 0 → Windows 读 restart page 时 UsaOffset=0 误解析 → 拒绝挂载。
        val logFileData = ByteArray((logFileClusters * bytesPerCluster).toInt()) { 0xFF.toByte() }
        sectors.add(logFileLcn * bytesPerCluster to logFileData)

        val bitmapData = ByteArray((bitmapClusters * bytesPerCluster).toInt())
        for ((start, count) in usedLcns) {
            for (c in 0L until count) {
                val lcn = start + c
                val byteIdx = (lcn / 8).toInt()
                val bit = (lcn % 8).toInt()
                bitmapData[byteIdx] = (bitmapData[byteIdx].toInt() or (1 shl bit)).toByte()
            }
        }
        sectors.add(bitmapLcn * bytesPerCluster to bitmapData)

        sectors.add(upcaseLcn * bytesPerCluster to buildUpcaseTable())

        val attrDefImage = ByteArray((attrDefClusters * bytesPerCluster).toInt())
        val attrDef = buildAttrDefTable()
        System.arraycopy(attrDef, 0, attrDefImage, 0, attrDef.size)
        sectors.add(attrDefLcn * bytesPerCluster to attrDefImage)

        // H2：MFT 记录分配位图数据。记录 0..23 标记已用（0..11 元数据 + 12..23 NTFS 保留区，
        //   allocMftRecord 从记录 24 起扫空闲），其余为 0。与 bitmap 全 0 不同——否则 chkdsk
        //   报「$MFT 已用记录未在位图置位」。位数以 totalMftRecords 为上界，防越界。
        val mftBitmapData = ByteArray((mftBitmapClusters * bytesPerCluster).toInt())
        val reservedRecords = minOf(24L, totalMftRecords)
        for (r in 0L until reservedRecords) {
            val byteIdx = (r / 8).toInt()
            val bit = (r % 8).toInt()
            mftBitmapData[byteIdx] = (mftBitmapData[byteIdx].toInt() or (1 shl bit)).toByte()
        }
        sectors.add(mftBitmapLcn * bytesPerCluster to mftBitmapData)

        return FatFormatter.FatImage(bytesPerSector = SECTOR, sectors = sectors)
    }

    /** 引导区（VBR + BPB，扇区 0..15 = 8KB）。 */
    internal fun buildBootRegion(
        sectorsPerCluster: Int, totalSectors: Long, mftLcn: Long, mftMirrLcn: Long, serial: Long,
    ): ByteArray {
        val boot = ByteArray(BOOT_SIZE)
        boot[0] = 0xEB.toByte(); boot[1] = 0x52; boot[2] = 0x90.toByte()   // jump
        System.arraycopy("NTFS    ".toByteArray(Charsets.US_ASCII), 0, boot, 3, 8)
        putU16(boot, 0x0B, SECTOR)
        boot[0x0D] = sectorsPerCluster.toByte()
        putU16(boot, 0x0E, 0); boot[0x10] = 0; putU16(boot, 0x11, 0); putU16(boot, 0x13, 0)
        boot[0x15] = 0xF8.toByte()       // media
        putU16(boot, 0x16, 0); putU16(boot, 0x18, 63); putU16(boot, 0x1A, 255)
        putU32(boot, 0x1C, 0L); putU32(boot, 0x20, 0L); putU32(boot, 0x24, 0x80008000L)
        putU64(boot, 0x28, totalSectors)
        putU64(boot, 0x30, mftLcn)
        putU64(boot, 0x38, mftMirrLcn)
        boot[0x40] = (-10).toByte()      // ClustersPerFileRecordSegment: 1024=2^10 → -10
        boot[0x41] = 0; boot[0x42] = 0; boot[0x43] = 0
        // H4：ClustersPerIndexBuffer 按真实簇大小编码，不再写死 1（4096 index buffer）。
        boot[0x44] = indexBufferCode(sectorsPerCluster * SECTOR).toByte()
        boot[0x45] = 0; boot[0x46] = 0; boot[0x47] = 0
        putU64(boot, 0x48, serial)       // volume serial
        putU32(boot, 0x50, 0L)           // checksum（ntfs-3g 留 0）
        boot[0x1FE] = 0x55; boot[0x1FF] = 0xAA.toByte()
        return boot
    }
}
