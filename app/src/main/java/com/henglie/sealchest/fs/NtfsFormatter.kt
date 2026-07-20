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
    // MFT 初始记录数：256 × 1024B = 256KB。扣除元数据 0..11 + NTFS 保留 12..23（allocMftRecord
    //   从 24 起扫），余 232 个用户文件/目录额度（原 32 仅余 8，测试手册「塞 50+ 文件」第 9 个即失败）。
    //   256KB 对任何 2 的幂簇大小（512..64K = 2^9..2^16）都整除（256KB=2^18），mftClusters 恒整。
    internal const val MFT_INITIAL_RECORDS = 256
    internal const val MFT_MIRR_RECORDS = 4

    internal const val ATTR_STANDARD_INFO = 0x10L
    internal const val ATTR_FILE_NAME = 0x30L
    internal const val ATTR_VOLUME_NAME = 0x60L
    internal const val ATTR_VOLUME_INFO = 0x70L
    internal const val ATTR_DATA = 0x80L
    internal const val ATTR_INDEX_ROOT = 0x90L
    internal const val ATTR_INDEX_ALLOCATION = 0xA0L
    internal const val ATTR_BITMAP = 0xB0L
    internal const val ATTR_END = 0xFFFFFFFFL

    internal const val FLAG_IN_USE = 0x0001
    internal const val FLAG_DIRECTORY = 0x0002
    // $Secure(记录9) 用 $SDH/$SII 视图索引而非 $I30 文件名索引 → 记录头须置 IS_VIEW_INDEX(0x08)，
    //   与真·Windows 一致（flags=0x09）。漏置 → chkdsk 报「Flags for file record segment 9 are incorrect」。
    internal const val FLAG_IS_VIEW_INDEX = 0x0008

    /**
     * NTFS 索引记录（index block）字节大小：**恒 4096**（与真·Windows 一致）。
     *   fsutil 金标准铁证：Windows format 8K/16K/... 簇 NTFS 的「Bytes Per Index Record Segment」
     *   恒为 4096，即使簇 > 4096（此时 index block < 簇，完全合法，boot[0x44] 用负数编码）。
     *   旧实现 max(4096,簇) 让大簇 index block=8192/16384/... → root $I30 在 superfloppy（桌面
     *   VeraCrypt 挂载）下 Windows 无法遍历 → chkdsk /f 判所有系统文件 orphan。逐簇 VeraCrypt
     *   就地替换验证：4K(idxBlk=4096) 系统文件 0 orphan；8K(idxBlk=8192) 系统文件全 orphan。
     */
    internal fun indexRecordSize(bytesPerCluster: Int): Int = INDEX_RECORD_SIZE

    /**
     * ClustersPerIndexBuffer 编码（boot[0x44] 与 $INDEX_ROOT+0x0C 同一编码，见 NtfsBoot.recordSize）。
     *   簇 ≤ 4096：index block=4096 ≥ 簇 → 正数簇计 4096/簇（512→8…4096→1）。
     *   簇 > 4096：index block=4096 < 簇 → 负数编码 -log2(4096)=-12（NtfsBoot.recordSize 解析
     *     负值 v 为 2^(-v) 字节，-12 → 4096）。与真·Windows 8K+ 簇 boot[0x44] 一致。
     *
     * 注：曾疑 $INDEX_ROOT+0x0C 用不同编码（block/512=8），真机实证否决——测试6(填-12) 与
     *   测试7(填8) 的 8K chkdsk 输出逐字节相同（仅时间戳差），$SDH/$SII/$I30 报错不变。
     *   两字段确用同一负 log2 编码（-12→4096 与 index_block_size(0x08)=4096 自洽；填 8 会解成
     *   8×8192≠4096 不自洽）。8K+ 报错根因在别处（$SDS 流布局，排查中），非此字段。
     */
    internal fun indexBufferCode(bytesPerCluster: Int): Int =
        if (INDEX_RECORD_SIZE >= bytesPerCluster) INDEX_RECORD_SIZE / bytesPerCluster
        else {
            var log2 = 0
            var v = INDEX_RECORD_SIZE
            while (v > 1) { v = v shr 1; log2++ }
            -log2
        }
    internal const val FILE_ATTR_SYSTEM = 0x06L               // HIDDEN|SYSTEM
    // NTFS 目录位是 file_attributes 的 0x10000000(I30_INDEX_PRESENT)，非 DOS 的 0x10。
    //   chkdsk 交叉校验：记录头 FLAG_DIRECTORY(0x16 位)、带 $I30 $INDEX_ROOT、$FILE_NAME/
    //   $STD_INFO 的 0x10000000 三者须一致，缺则报「文件属性不一致」并重写。旧值 0x16 用错 DOS 位。
    internal const val FILE_ATTR_I30_INDEX_PRESENT = 0x10000000L
    internal const val FILE_ATTR_DIR_SYSTEM = 0x10000006L     // I30_INDEX_PRESENT|HIDDEN|SYSTEM
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

        // 引导区 8KB 固定，但簇 > 8KB 时 8192/bpc 向下取整 = 0 → mftLcn=bootLcn+0=0
        //   → 后写的 MFT 镜像覆盖偏移 0 的引导扇区 → NTFS 签名被冲掉 → 挂载分发落到 FAT
        //   解析器报「非 FAT 引导扇区」（16K/32K/64K 大簇必炸）。引导区至少占 1 簇：ceil。
        val bootClusters = (BOOT_SIZE.toLong() + bytesPerCluster - 1) / bytesPerCluster
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
        // $Secure 的 $SDS 数据流：共享 SD + 0x40000 镜像。放 attrDef 之后、mftBitmap 之前。
        //   sdsRealSize 非簇对齐无妨（稀疏写，簇内余量为加密零）。hash 只算一次，多处复用。
        val sharedSd = NtfsSecure.buildSharedSd()
        val sdsHash = NtfsSecure.securityHash(sharedSd)
        val sdsRealSize = NtfsSecure.sdsDataSize(sharedSd)
        val sdsClusters = (sdsRealSize + bytesPerCluster - 1) / bytesPerCluster
        val sdsLcn = attrDefLcn + attrDefClusters
        val mftBitmapLcn = sdsLcn + sdsClusters
        // root $I30 LARGE_INDEX 的 INDX 叶子（VCN=0）。index block 恒 4096（见 indexRecordSize）。
        //   占簇数 = ceil(4096/簇)：簇≤4096→4096/簇（512→8…4096→1），簇>4096→1 簇（index block
        //   4096 < 簇，占 1 整簇，簇内后半空闲）。用 ceil 防大簇下整除得 0。
        val idxRecSize = indexRecordSize(bytesPerCluster)
        val rootIndxClusters = ((idxRecSize.toLong() + bytesPerCluster - 1) / bytesPerCluster).coerceAtLeast(1)
        val rootIndxLcn = mftBitmapLcn + mftBitmapClusters
        val lastMetaLcn = rootIndxLcn + rootIndxClusters - 1

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

        // H2：卷尾备份引导扇区（sector totalSectors-1）所在簇必须在 $Bitmap 标 used，
        //   否则该簇空闲 → 写文件时被 allocContiguousClusters 分出去 → 覆盖备份 VBR，
        //   chkdsk 报「备份引导扇区无效」。lcn=(totalSectors-1)/spc（整除时=totalClusters-1）。
        val backupVbrLcn = (totalSectors - 1) / sectorsPerCluster
        val usedLcns = listOf(
            bootLcn to bootClusters, mftLcn to mftClusters, logFileLcn to logFileClusters,
            bitmapLcn to bitmapClusters, upcaseLcn to upcaseClusters,
            attrDefLcn to attrDefClusters, mftBitmapLcn to mftBitmapClusters,
            sdsLcn to sdsClusters,
            rootIndxLcn to rootIndxClusters,
            mftMirrLcn to mftMirrClusters,
            backupVbrLcn to 1L,
        )

        val serial = randomSerial()
        val now = msToNtfsTime(System.currentTimeMillis())
        val rootRef = mftRef(5L)

        val sectors = ArrayList<Pair<Long, ByteArray>>()

        val boot = buildBootRegion(sectorsPerCluster, totalSectors, mftLcn, mftMirrLcn, serial)
        sectors.add(0L to boot)

        val mftRecords = Array(MFT_INITIAL_RECORDS) { ByteArray(MFT_RECORD_SIZE) }
        mftRecords[0] = buildMftRecord(
            mftLcn, mftClusters, bytesPerCluster, now,
            mftBitmapLcn, mftBitmapClusters, mftBitmapRealSize,
        )
        mftRecords[1] = buildMftMirrRecord(mftMirrLcn, mftMirrClusters, bytesPerCluster, now, rootRef)
        mftRecords[2] = buildLogFileRecord(logFileLcn, logFileClusters, bytesPerCluster, now, rootRef)
        mftRecords[3] = buildVolumeRecord(volumeLabel, now, rootRef)
        mftRecords[4] = buildAttrDefRecord(attrDefLcn, attrDefClusters, bytesPerCluster, now, rootRef)
        mftRecords[5] = buildRootDirRecord(now, rootRef, bytesPerCluster, rootIndxLcn, rootIndxClusters)
        mftRecords[6] = buildBitmapRecord(bitmapLcn, bitmapClusters, bytesPerCluster, bitmapBytes, now, rootRef)
        mftRecords[7] = buildBootFileRecord(bootLcn, bootClusters, bytesPerCluster, now, rootRef)
        mftRecords[8] = buildBadClusRecord(totalClusters, bytesPerCluster, now, rootRef)
        mftRecords[9] = buildSecureRecord(now, rootRef, bytesPerCluster, sdsLcn, sdsClusters, sharedSd, sdsHash)
        mftRecords[10] = buildUpcaseFileRecord(upcaseLcn, upcaseClusters, bytesPerCluster, now, rootRef)
        mftRecords[11] = buildExtendRecord(now, rootRef, bytesPerCluster)

        // Bug4：记录头 0x2C(本记录 MFT 号，NTFS 3.1 字段)。RecBuilder 不知自身号，此处统一补。
        //   0x2C..2F 不落在任一扇区末 2 字节(USA 保护位)，stampUsa 后改它安全。运行时侧
        //   NtfsDataOps 建记录时已写此字段，仅造盘 12 条元数据缺，补齐三方一致。
        // 序列号(0x10)同理统一补：真·Windows rec1..15 的 seq=记录号(rec0=1)。RecBuilder 硬编码 1，
        //   使 rec2..11 头 seq(=1)≠记录号 + 子记录 $FILE_NAME.parentSeq 与根目录 seq 对不上 →
        //   chkdsk 报「检测到不正确的信息」。0x10..11 也不在扇区末 USA 保护位，stampUsa 后改安全。
        for (i in 0 until 12) {
            putU32(mftRecords[i], 0x2C, i.toLong())
            putU16(mftRecords[i], 0x10, mftSeqOf(i.toLong()))
        }

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
                // 卷外簇跳过：totalSectors 非簇整数倍时 backupVbrLcn 可能 = totalClusters
                // （落在卷尾不足一簇的尾部，超出有效簇编号）——此时不占任何 LCN，不标、防越界。
                if (lcn >= totalClusters) continue
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

        // root $I30 INDX 叶子（VCN=0）：12 个索引项（11 系统文件 + "."），全 ns=3
        //   (NS_WIN32_AND_DOS)，按 $FILE_NAME 字符字典序排序（参考真实 Windows C: 盘 MFT#5 dump）。
        val rootFnContents = listOf<Pair<Long, ByteArray>>(
            mftRef(4L)  to buildFileNameContent(rootRef, "\$AttrDef",  now),
            mftRef(8L)  to buildFileNameContent(rootRef, "\$BadClus", now),
            mftRef(6L)  to buildFileNameContent(rootRef, "\$Bitmap",  now),
            mftRef(7L)  to buildFileNameContent(rootRef, "\$Boot",    now),
            mftRef(11L) to buildFileNameContent(rootRef, "\$Extend",  now, isDir = true),
            mftRef(2L)  to buildFileNameContent(rootRef, "\$LogFile", now),
            mftRef(0L)  to buildFileNameContent(rootRef, "\$MFT",     now),
            mftRef(1L)  to buildFileNameContent(rootRef, "\$MFTMirr", now),
            mftRef(9L)  to buildFileNameContent(rootRef, "\$Secure",  now),
            mftRef(10L) to buildFileNameContent(rootRef, "\$UpCase",  now),
            mftRef(3L)  to buildFileNameContent(rootRef, "\$Volume",  now),
            mftRef(5L)  to buildFileNameContent(rootRef, ".",         now, ns = 3, isDir = true),
        )
        val rootIndxLeaf = buildRootIndxLeafRecord(bytesPerCluster, 0L, rootFnContents)
        sectors.add(rootIndxLcn * bytesPerCluster to rootIndxLeaf)

        // $Secure 的 $SDS 数据流：primary@0 + mirror@0x40000，两份 header 都记 primary offset=0。
        //   稀疏区（0..0x40000）在密文里是加密零，chkdsk 不读，只读两个 entry。
        val sdsStream = NtfsSecure.buildSdsStream(sharedSd, NtfsSecure.FIRST_SECURITY_ID, sdsHash)
        sectors.add(sdsLcn * bytesPerCluster to sdsStream)

        // 卷尾备份引导扇区（NTFS 规范：最末扇区 sector N-1 存 VBR 副本，chkdsk 据此校验
        //   「备份引导扇区」）。内容 = buildBootRegion 前 512 字节（VBR+BPB）的拷贝。
        //   偏移 (totalSectors-1)*SECTOR 与 BPB.TotalSectors=N-1 自洽。
        sectors.add((totalSectors - 1) * SECTOR to boot.copyOfRange(0, SECTOR))

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
        putU32(boot, 0x1C, 0L); putU32(boot, 0x20, 0L)
        // 0x24-0x27：physical drive number(0x80@0x24) + reserved(0x25) + extended boot
        //   signature(0x80@0x26) + reserved(0x27)。小端 u32 = 0x00800080（逐字节 80 00 80 00），
        //   与 Windows format 产物一致。旧值 0x80008000 字节序写反（→ 0x24=0,0x26=0），分区模式
        //   下 Windows 用 MBR 挂载忽略此字段故 chkdsk 不报；但 superfloppy 模式（VeraCrypt 挂载）
        //   NTFS.sys 直接校验 VBR，ext boot signature(0x26) 缺失 → 拒挂 → 卷报「1392 损坏」。
        putU32(boot, 0x24, 0x00800080L)
        // BPB.TotalSectors = N-1：NTFS 规范规定该字段不含最末扇区（备份引导扇区所在），
        // 卷真实扇区数为 N，BPB 声明 N-1。写满值会让 chkdsk 误判卷大小并报备份引导扇区无效。
        putU64(boot, 0x28, totalSectors - 1)
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
