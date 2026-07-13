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
 * FAT 类型按「数据区簇总数」自动选（与 [Bpb.parse] 判型同一阈值）：簇数 < 4085 → FAT12，
 * < 65525 且 < 512MB → FAT16，≥ 512MB → FAT32。写侧布局必须与读侧判型一致，否则小卷
 * 写成 FAT16 却被按簇数判为 FAT12，簇链按 12 位错位解析而报废容器。
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
    fun buildEmptyFat(volumeSizeBytes: Long, clusterSize: Int = 0): FatImage {
        require(volumeSizeBytes % SECTOR == 0L) { "数据区须 512 对齐：$volumeSizeBytes" }
        val totalSectors = volumeSizeBytes / SECTOR
        require(totalSectors >= 64) { "数据区过小，放不下 FAT：$totalSectors 扇区" }
        // X2：clusterSize=0 自动沿用阶梯，否则换算成 sectorsPerCluster 覆盖阶梯。
        // clusterSize 须为 512 倍数（FAT 簇大小是扇区整数倍），非法抛 IllegalArgumentException。
        val overrideSpc: Int? = if (clusterSize <= 0) null else {
            require(clusterSize % SECTOR == 0) { "簇大小须 512 倍数：$clusterSize" }
            val spc = clusterSize / SECTOR
            require(spc >= 1 && spc <= 128) { "簇大小越界（1..128 扇区）：$spc" }
            spc
        }

        return when (resolveFatType(totalSectors, overrideSpc)) {
            FatType.FAT32 -> buildFat32(totalSectors, overrideSpc)
            FatType.FAT12 -> buildFat12(totalSectors, overrideSpc)
            FatType.FAT16 -> buildFat16(totalSectors, overrideSpc)
        }
    }

    /**
     * 返回 FAT 根目录区在数据区内的（逻辑偏移, 字节数），供 [VolumeCreator] 在
     * randomFill 后显式清零用。
     *
     * 背景：[buildEmptyFat] 只写引导扇区 + FAT 表首扇区，不显式写根目录区
     * （FAT16 固定根目录区 / FAT32 根目录簇2），依赖数据区本就全零的假设。
     * 当 randomFill=true 用随机字节铺满数据区后，该假设不成立，根目录区残留
     * 随机字节会被 FAT 解析成幽灵目录项（如"随机文件1"）。故需在 randomFill 后
     * 对根目录区写零（走 VolumeReader.write，经 XTS 加密）。
     *
     * - FAT16：固定根目录区位于 FAT2 之后、数据簇之前，大小 = RootDirEntries * 32。
     * - FAT32：根目录首簇（簇2）位于簇堆起点，大小 = bytesPerCluster。
     *
     * 参数计算须与 [buildFat16] / [buildFat32] 保持一致，改其一须同步改本处。
     *
     * @return 根目录区（偏移, 大小）；仅 FAT16/FAT32 有效。
     */
    fun rootDirRegion(volumeSizeBytes: Long, clusterSize: Int = 0): Pair<Long, Int> {
        require(volumeSizeBytes % SECTOR == 0L) { "数据区须 512 对齐：$volumeSizeBytes" }
        val totalSectors = volumeSizeBytes / SECTOR
        val overrideSpc: Int? = if (clusterSize <= 0) null else {
            require(clusterSize % SECTOR == 0) { "簇大小须 512 倍数：$clusterSize" }
            val spc = clusterSize / SECTOR
            require(spc in 1..128) { "簇大小越界（1..128 扇区）：$spc" }
            spc
        }
        return when (resolveFatType(totalSectors, overrideSpc)) {
            FatType.FAT32 -> rootDirRegionFat32(totalSectors, overrideSpc)
            FatType.FAT12 -> rootDirRegionFat12(totalSectors, overrideSpc)
            FatType.FAT16 -> rootDirRegionFat16(totalSectors, overrideSpc)
        }
    }

    /**
     * 返回 FAT 卷所有须清零的元数据区（FAT 表两份 + 根目录区）的 (偏移, 大小) 列表。
     * 供 [VolumeCreator] 在写文件系统结构前显式清零——Android 创建新文件不保证零填充，
     * 残留数据会被 FAT 解析成乱码目录项/幽灵簇链。不管 randomFill 开不开都须调。
     */
    fun metadataClearRegions(volumeSizeBytes: Long, clusterSize: Int = 0): List<Pair<Long, Int>> {
        require(volumeSizeBytes % SECTOR == 0L) { "数据区须 512 对齐：$volumeSizeBytes" }
        val totalSectors = volumeSizeBytes / SECTOR
        val overrideSpc: Int? = if (clusterSize <= 0) null else {
            val spc = clusterSize / SECTOR
            require(spc in 1..128) { "簇大小越界（1..128 扇区）：$spc" }
            spc
        }
        return when (resolveFatType(totalSectors, overrideSpc)) {
            FatType.FAT32 -> metadataRegionsFat32(totalSectors, overrideSpc)
            FatType.FAT12 -> metadataRegionsFat12(totalSectors, overrideSpc)
            FatType.FAT16 -> metadataRegionsFat16(totalSectors, overrideSpc)
        }
    }

    private fun rootDirRegionFat16(totalSectors: Long, overrideSpc: Int?): Pair<Long, Int> {
        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
            volumeSizeBytes < 16L * 1024 * 1024 -> 4     // <16MB: 2KB 簇
            volumeSizeBytes < 128L * 1024 * 1024 -> 8    // <128MB: 4KB 簇
            else -> 16                                   // 8KB 簇
        }
        val reservedSectors = 1
        val numFats = 2
        val rootEntries = 512                            // FAT16 惯例 512 项
        val rootDirSectors = (rootEntries * 32 + SECTOR - 1) / SECTOR
        val dataSectorsApprox = totalSectors - reservedSectors - rootDirSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = (((clustersApprox + 2) * 2) + SECTOR - 1) / SECTOR
        val rootDirOffset = (reservedSectors + numFats * fatSectors) * SECTOR
        val rootDirSize = rootDirSectors * SECTOR
        return rootDirOffset to rootDirSize
    }

    private fun rootDirRegionFat32(totalSectors: Long, overrideSpc: Int?): Pair<Long, Int> {
        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
            volumeSizeBytes < 8L * 1024 * 1024 * 1024 -> 8    // <8GB: 4KB 簇
            else -> 16                                        // 8KB 簇
        }
        val reservedSectors = 32                         // FAT32 惯例 32
        val numFats = 2
        val dataSectorsApprox = totalSectors - reservedSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = (((clustersApprox + 2) * 4) + SECTOR - 1) / SECTOR   // FAT32 每项 4 字节
        val cluster2Offset = (reservedSectors + numFats * fatSectors) * SECTOR
        val clusterSizeBytes = sectorsPerCluster * SECTOR
        return cluster2Offset to clusterSizeBytes
    }

    // ---- 元数据清零区域（FAT 表两份 + 根目录）----
    // 参数计算与 rootDirRegionFatXX / buildFatXX 完全一致，改其一须同步。

    private fun metadataRegionsFat12(totalSectors: Long, overrideSpc: Int?): List<Pair<Long, Int>> {
        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
            volumeSizeBytes < 16L * 1024 * 1024 -> 4
            volumeSizeBytes < 128L * 1024 * 1024 -> 8
            else -> 16
        }
        val reservedSectors = 1
        val numFats = 2
        val rootEntries = 512
        val rootDirSectors = (rootEntries * 32 + SECTOR - 1) / SECTOR
        val dataSectorsApprox = totalSectors - reservedSectors - rootDirSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = fatSectors12(clustersApprox)
        val fatLen = (fatSectors * SECTOR).toInt()
        val fat1Off = reservedSectors.toLong() * SECTOR
        val fat2Off = (reservedSectors + fatSectors) * SECTOR
        val rootOff = (reservedSectors + numFats * fatSectors) * SECTOR
        val rootLen = rootDirSectors * SECTOR
        return listOf(fat1Off to fatLen, fat2Off to fatLen, rootOff to rootLen)
    }

    private fun metadataRegionsFat16(totalSectors: Long, overrideSpc: Int?): List<Pair<Long, Int>> {
        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
            volumeSizeBytes < 16L * 1024 * 1024 -> 4
            volumeSizeBytes < 128L * 1024 * 1024 -> 8
            else -> 16
        }
        val reservedSectors = 1
        val numFats = 2
        val rootEntries = 512
        val rootDirSectors = (rootEntries * 32 + SECTOR - 1) / SECTOR
        val dataSectorsApprox = totalSectors - reservedSectors - rootDirSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = (((clustersApprox + 2) * 2) + SECTOR - 1) / SECTOR
        val fatLen = (fatSectors * SECTOR).toInt()
        val fat1Off = reservedSectors.toLong() * SECTOR
        val fat2Off = (reservedSectors + fatSectors) * SECTOR
        val rootOff = (reservedSectors + numFats * fatSectors) * SECTOR
        val rootLen = rootDirSectors * SECTOR
        return listOf(fat1Off to fatLen, fat2Off to fatLen, rootOff to rootLen)
    }

    private fun metadataRegionsFat32(totalSectors: Long, overrideSpc: Int?): List<Pair<Long, Int>> {
        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
            volumeSizeBytes < 8L * 1024 * 1024 * 1024 -> 8
            else -> 16
        }
        val reservedSectors = 32
        val numFats = 2
        val dataSectorsApprox = totalSectors - reservedSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = (((clustersApprox + 2) * 4) + SECTOR - 1) / SECTOR
        val fatLen = (fatSectors * SECTOR).toInt()
        val fat1Off = reservedSectors.toLong() * SECTOR
        val fat2Off = (reservedSectors + fatSectors) * SECTOR
        val cluster2Off = (reservedSectors + numFats * fatSectors) * SECTOR
        val clusterSizeBytes = sectorsPerCluster * SECTOR
        return listOf(fat1Off to fatLen, fat2Off to fatLen, cluster2Off to clusterSizeBytes)
    }

    // ================================================================
    //  FAT 类型选型（与 Bpb.parse 读侧完全同式，保证写读自洽）
    // ================================================================
    /**
     * 选定 FAT 类型 —— 唯一权威。三处入口（buildEmptyFat / rootDirRegion /
     * metadataClearRegions）与三个 buildFatXX 全部以本函数为准，杜绝各处判型分裂。
     *
     * 核心：写侧判型必须用「按目标类型布局写出后、读侧 [Bpb.parse] 会重算出的簇数」
     * 来判，否则会出现「写 FAT16 布局却被读成 FAT12/FAT32」的簇链错位报废。
     * 读侧簇数 = totalSectors − reserved − numFats×fatSectors − rootDirSectors，再 /spc；
     * 其中 fatSectors 依类型的每项字节数（FAT12=1.5 / FAT16=2 / FAT32=4）不同。
     *
     * 判定序（用 FAT16 布局的读侧簇数 c16 为主锚）：
     *   - 卷 ≥ 512MB           → FAT32（大卷惯例）
     *   - c16 > 65524          → FAT32（簇太多，FAT16 装不下；如小簇配大卷）
     *   - c16 ≥ 4085           → FAT16（读回 c16∈[4085,65524]，自洽）
     *   - 否则                 → FAT12（读回 c12<4085，自洽）
     * 各 buildFatXX 入口另有 require 兜底：任何越界组合宁可创建失败，绝不写出报废卷。
     */
    private fun resolveFatType(totalSectors: Long, overrideSpc: Int?): FatType {
        val volumeSizeBytes = totalSectors * SECTOR
        // 逐型自校验：用读侧 Bpb.parse 同款簇数公式（readClustersXX）判每一型是否落在
        // 其合法区间。选中的型，读侧用同布局重算必落同区间 → 写读判型闭合，杜绝窄带错位。
        val spc1216 = spcFat1216(volumeSizeBytes, overrideSpc)
        val c12 = readClusters12(totalSectors, spc1216)
        if (c12 < 4085) return FatType.FAT12
        val c16 = readClusters16(totalSectors, spc1216)
        if (c16 in 4085..65524) return FatType.FAT16
        val spc32 = spcFat32(volumeSizeBytes, overrideSpc)
        val c32 = readClusters32(totalSectors, spc32)
        if (c32 >= 65525) return FatType.FAT32
        // 落空：该几何无自洽 FAT 类型（典型是极端 override 簇大小）。绝不写出错位容器，
        // 宁可拒绝创建（VolumeCreator 会把异常转成失败）。
        error("无自洽 FAT 类型：totalSectors=$totalSectors override=$overrideSpc c12=$c12 c16=$c16 c32=$c32（请换簇大小或容量）")
    }

    /** FAT12/16 簇大小阶梯（overrideSpc 非空时用用户指定）。 */
    private fun spcFat1216(volumeSizeBytes: Long, overrideSpc: Int?): Int = overrideSpc ?: when {
        volumeSizeBytes < 16L * 1024 * 1024 -> 4     // <16MB: 2KB 簇
        volumeSizeBytes < 128L * 1024 * 1024 -> 8    // <128MB: 4KB 簇
        else -> 16                                   // 8KB 簇
    }

    /** FAT32 簇大小阶梯。 */
    private fun spcFat32(volumeSizeBytes: Long, overrideSpc: Int?): Int = overrideSpc ?: when {
        volumeSizeBytes < 8L * 1024 * 1024 * 1024 -> 8    // <8GB: 4KB 簇
        else -> 16                                        // 8KB 簇
    }

    /** 读侧（Bpb.parse）对「按 FAT16 布局写出的卷」会重算出的数据区簇总数。reserved=1/numFats=2/root=512。 */
    private fun readClusters16(totalSectors: Long, spc: Int): Int {
        val rootDirSectors = (512 * 32 + SECTOR - 1) / SECTOR
        val clustersApprox = (totalSectors - 1 - rootDirSectors) / spc
        val fatSectors = (((clustersApprox + 2) * 2) + SECTOR - 1) / SECTOR
        val dataSectors = totalSectors - 1 - 2L * fatSectors - rootDirSectors
        return (dataSectors / spc).toInt()
    }

    /** 读侧对「按 FAT12 布局写出的卷」会重算出的数据区簇总数。与 [buildFat12] fatSectors 同式。 */
    private fun readClusters12(totalSectors: Long, spc: Int): Int {
        val rootDirSectors = (512 * 32 + SECTOR - 1) / SECTOR
        val clustersApprox = (totalSectors - 1 - rootDirSectors) / spc
        val fatSectors = fatSectors12(clustersApprox)
        val dataSectors = totalSectors - 1 - 2L * fatSectors - rootDirSectors
        return (dataSectors / spc).toInt()
    }

    /** 读侧对「按 FAT32 布局写出的卷」会重算出的数据区簇总数。reserved=32/numFats=2/root=0。 */
    private fun readClusters32(totalSectors: Long, spc: Int): Int {
        val clustersApprox = (totalSectors - 32) / spc
        val fatSectors = (((clustersApprox + 2) * 4) + SECTOR - 1) / SECTOR
        val dataSectors = totalSectors - 32 - 2L * fatSectors
        return (dataSectors / spc).toInt()
    }

    /** FAT12 每份 FAT 扇区数：每项 1.5 字节，含首 2 个保留项。ceil((n+2)*3/2) 字节后按扇区上取整。 */
    private fun fatSectors12(clustersApprox: Long): Long {
        val fatBytes = ((clustersApprox + 2) * 3 + 1) / 2   // ceil((n+2)*1.5)
        return (fatBytes + SECTOR - 1) / SECTOR
    }

    // ================================================================
    //  FAT12
    // ================================================================
    private fun rootDirRegionFat12(totalSectors: Long, overrideSpc: Int?): Pair<Long, Int> {
        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
            volumeSizeBytes < 16L * 1024 * 1024 -> 4
            volumeSizeBytes < 128L * 1024 * 1024 -> 8
            else -> 16
        }
        val reservedSectors = 1
        val numFats = 2
        val rootEntries = 512
        val rootDirSectors = (rootEntries * 32 + SECTOR - 1) / SECTOR
        val dataSectorsApprox = totalSectors - reservedSectors - rootDirSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = fatSectors12(clustersApprox)
        val rootDirOffset = (reservedSectors + numFats * fatSectors) * SECTOR
        val rootDirSize = rootDirSectors * SECTOR
        return rootDirOffset to rootDirSize.toInt()
    }

    /**
     * 生成空 FAT12 镜像。严格镜像 [buildFat16]，仅三处按 FAT12 规范改：
     *  1. BS_FilSysType 写 "FAT12   "（0x36）。
     *  2. FAT[0]/[1] 保留项按 12 位布局：F8 FF FF（首项 0xFF8=媒体字节，次项 0xFFF=EOC，
     *     两项共 3 字节交错）。
     *  3. 每份 FAT 扇区数按 12 位（1.5 字节/项）算。
     * 其余（reserved=1、numFats=2、rootEntries=512、簇大小阶梯、BPB 公共字段）与 FAT16 相同。
     */
    private fun buildFat12(totalSectors: Long, overrideSpc: Int? = null): FatImage {
        val sectors = mutableListOf<Pair<Long, ByteArray>>()

        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
            volumeSizeBytes < 16L * 1024 * 1024 -> 4     // <16MB: 2KB 簇
            volumeSizeBytes < 128L * 1024 * 1024 -> 8    // <128MB: 4KB 簇
            else -> 16                                   // 8KB 簇
        }
        val reservedSectors = 1
        val numFats = 2
        val rootEntries = 512                            // 与 FAT16 惯例一致
        val rootDirSectors = (rootEntries * 32 + SECTOR - 1) / SECTOR

        // 估算数据簇数，反推每份 FAT 扇区数（FAT12 每项 1.5 字节，含首 2 个保留项）。
        val dataSectorsApprox = totalSectors - reservedSectors - rootDirSectors
        val clustersApprox = dataSectorsApprox / sectorsPerCluster
        val fatSectors = fatSectors12(clustersApprox)

        // 兜底：读侧 Bpb.parse 重算的簇数必须 <4085 才是合法 FAT12，否则写读判型分裂 → 报废。
        // 正常路径 resolveFatType 已保证；这里再挡一层，越界宁可创建失败绝不写坏卷。
        val readCount = readClusters12(totalSectors, sectorsPerCluster)
        require(readCount in 1 until 4085) {
            "FAT12 簇数越界：$readCount（须 1..4084，请换簇大小/容量）"
        }

        // ---- 引导扇区（BPB）----
        val boot = ByteArray(SECTOR)
        writeBpbCommon(boot, sectorsPerCluster, reservedSectors, numFats, totalSectors)
        putShort(boot, 0x11, rootEntries)                // BPB_RootEntCnt
        putShort(boot, 0x16, fatSectors.toInt())         // BPB_FATSz16
        boot[0x15] = 0xF8.toByte()                       // 媒体类型（固定盘）
        // FAT12 扩展引导记录（与 FAT16 同在 0x24 起）
        boot[0x24] = 0x80.toByte()                       // BS_DrvNum
        boot[0x26] = 0x29                                // BS_BootSig
        writeFsType(boot, 0x36, "FAT12   ")              // BS_FilSysType
        boot[0x1FE] = 0x55                               // 引导扇区签名
        boot[0x1FF] = 0xAA.toByte()
        sectors.add(0L to boot)

        // ---- FAT 表首扇区：前 2 项为保留项（12 位交错布局）----
        // FAT12: 首项=0xFF8（媒体字节），次项=0xFFF（EOC）。两项共 3 字节：F8 FF FF。
        val fat0 = ByteArray(SECTOR)
        fat0[0] = 0xF8.toByte(); fat0[1] = 0xFF.toByte(); fat0[2] = 0xFF.toByte()
        val fat1Start = reservedSectors.toLong() * SECTOR
        val fat2Start = (reservedSectors + fatSectors) * SECTOR
        sectors.add(fat1Start to fat0)
        sectors.add(fat2Start to fat0.copyOf())

        return FatImage(SECTOR, sectors)
    }

    // ================================================================
    //  FAT16
    // ================================================================
    private fun buildFat16(totalSectors: Long, overrideSpc: Int? = null): FatImage {
        val sectors = mutableListOf<Pair<Long, ByteArray>>()

        val volumeSizeBytes = totalSectors * SECTOR
        // 簇大小：overrideSpc 非空时用用户指定（X2），否则按卷大小自动选（保证簇数落在 FAT16 合法区间 4085..65524）。
        val sectorsPerCluster = overrideSpc ?: when {
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

        // 兜底：读侧簇数必须落在 FAT16 合法区间，否则宁可创建失败（绝不写出被读成
        // FAT12/FAT32 的错位卷）。resolveFatType 已保证正常路径到此，此为纵深防御。
        val readCnt = readClusters16(totalSectors, sectorsPerCluster)
        require(readCnt in 4085..65524) {
            "FAT16 簇数越界：$readCnt（合法 4085..65524，请换簇大小或容量）"
        }

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
    private fun buildFat32(totalSectors: Long, overrideSpc: Int? = null): FatImage {
        val sectors = mutableListOf<Pair<Long, ByteArray>>()

        val volumeSizeBytes = totalSectors * SECTOR
        val sectorsPerCluster = overrideSpc ?: when {
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
