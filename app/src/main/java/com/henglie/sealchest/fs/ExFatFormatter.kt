package com.henglie.sealchest.fs

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * 空 exFAT 文件系统镜像生成器（B2 创建容器，fsType=1）。
 *
 * VeraCrypt 桌面版对 exFAT 是把裸卷挂成盘符后调 Windows FormatEx（fmifs.dll）格式化，
 * 其源码里没有 exFAT 造盘逻辑（见 Format.c:802）。安卓无等价系统设施，故本类从零按
 * Microsoft exFAT file system specification（2019）字节级自研。
 *
 * 产出复用 [FatFormatter.FatImage] 稀疏格式（bytesPerSector + 卷内逻辑偏移到字节段），
 * 由 [VolumeCreator] 逐段经 XTS 加密写入数据区。逻辑偏移 0 = 数据区首字节 = 主引导扇区。
 *
 * 空 exFAT 布局（512B 扇区）：
 *   扇区 0        主引导扇区（VBR）
 *   扇区 1..8     扩展引导扇区（末 4 字节 0xAA550000）
 *   扇区 9        OEM 参数（全 0）
 *   扇区 10       保留（全 0）
 *   扇区 11       主引导校验和（对扇区 0..10 逐字节滚动，重复填满整扇区）
 *   扇区 12..23   备份引导区（扇区 0..11 的镜像）
 *   FatOffset..   FAT 区（每项 4 字节）
 *   簇堆：簇 2 分配位图 / 簇 3.. upcase 表 / 其后 根目录
 *
 * 判据（唯一）：桌面 VeraCrypt 挂载 + Windows 资源管理器可读写 + chkdsk 干净。待恒烈真机验。
 */
object ExFatFormatter {

    private const val SECTOR = 512
    private const val FAT_OFFSET_SEC = 24          // boot region(main+backup)=24 扇区，FAT 紧随其后
    private const val ENTRY = 32                    // 目录项定长

    // exFAT 目录项类型字节（bit7=InUse）。
    private const val TYPE_BITMAP = 0x81
    private const val TYPE_UPCASE = 0x82
    private const val TYPE_LABEL = 0x83

    /**
     * 为 [volumeSizeBytes] 大小数据区生成空 exFAT 镜像。
     *
     * @param volumeSizeBytes 数据区字节数（不含卷头组），512 对齐。
     * @param clusterSizeOverride 大于 0 时强制簇字节大小（512 倍数、2 的幂扇区），否则按容量阶梯。
     * @param volumeLabel 卷标（最多 11 字符，超出截断），空串则写空卷标项。
     */
    fun buildEmpty(
        volumeSizeBytes: Long,
        clusterSizeOverride: Int = 0,
        volumeLabel: String = "",
    ): FatFormatter.FatImage {
        require(volumeSizeBytes % SECTOR == 0L) { "数据区须 512 对齐：$volumeSizeBytes" }
        val volumeLengthSec = volumeSizeBytes / SECTOR
        require(volumeLengthSec >= 128) { "exFAT 数据区过小：$volumeLengthSec 扇区（须至少 64KB）" }

        // ---- 簇大小 ----
        val bytesPerCluster = if (clusterSizeOverride > 0) {
            require(clusterSizeOverride % SECTOR == 0) { "簇大小须 512 倍数：$clusterSizeOverride" }
            clusterSizeOverride
        } else when {
            volumeSizeBytes < 256L * 1024 * 1024 -> 4096
            volumeSizeBytes < 32L * 1024 * 1024 * 1024 -> 32768
            else -> 131072
        }
        val sectorsPerCluster = bytesPerCluster / SECTOR
        val spcShift = Integer.numberOfTrailingZeros(sectorsPerCluster)
        require((1 shl spcShift) == sectorsPerCluster) { "簇扇区数须 2 的幂：$sectorsPerCluster" }

        // ---- FAT 长度 + 簇堆偏移（不迭代：用簇数上界估 FAT，多余 FAT 项留 0 无害）----
        val maxClusters = (volumeLengthSec - FAT_OFFSET_SEC) / sectorsPerCluster
        require(maxClusters >= 8) { "exFAT 容器过小，放不下元数据" }
        val fatBytes = (maxClusters + 2) * 4
        val fatLengthSec = ((fatBytes + SECTOR - 1) / SECTOR).toInt()
        var heapStartSec = FAT_OFFSET_SEC + fatLengthSec
        // 簇堆首扇区对齐到簇边界。
        heapStartSec = ((heapStartSec + sectorsPerCluster - 1) / sectorsPerCluster) * sectorsPerCluster
        val clusterHeapOffsetSec = heapStartSec
        val clusterCount = (volumeLengthSec - clusterHeapOffsetSec) / sectorsPerCluster
        require(clusterCount >= 4) { "exFAT 可用簇不足：$clusterCount" }

        // ---- 元数据布局：簇 2 位图 / upcase / 根目录 ----
        val bitmapBytes = (clusterCount + 7) / 8
        val bitmapClusters = ((bitmapBytes + bytesPerCluster - 1) / bytesPerCluster).toInt()
        val bitmapFirstCluster = 2L

        val upcase = buildUpcaseCompressed()
        val upcaseChecksum = tableChecksum(upcase)
        val upcaseClusters = (upcase.size + bytesPerCluster - 1) / bytesPerCluster
        val upcaseFirstCluster = bitmapFirstCluster + bitmapClusters

        val rootFirstCluster = upcaseFirstCluster + upcaseClusters
        val rootClusters = 1
        val lastUsedCluster = rootFirstCluster + rootClusters - 1
        require(lastUsedCluster - 2 < clusterCount) {
            "exFAT 元数据放不下：需簇 2..$lastUsedCluster，仅 $clusterCount 簇"
        }

        val sectors = ArrayList<Pair<Long, ByteArray>>()

        // ================= 引导区（主 + 备份）=================
        val bootRegion = buildBootRegion(
            volumeLengthSec = volumeLengthSec,
            fatOffsetSec = FAT_OFFSET_SEC,
            fatLengthSec = fatLengthSec,
            clusterHeapOffsetSec = clusterHeapOffsetSec,
            clusterCount = clusterCount,
            rootFirstCluster = rootFirstCluster,
            bytesPerSectorShift = 9,
            spcShift = spcShift,
        )
        sectors.add(0L to bootRegion)                          // 主引导区 扇区 0..11
        sectors.add((12L * SECTOR) to bootRegion.copyOf())     // 备份引导区 扇区 12..23

        // ================= FAT =================
        val fat = ByteArray(fatLengthSec * SECTOR)
        putU32(fat, 0, 0xFFFFFFF8L)   // FAT[0] 媒体描述符
        putU32(fat, 4, 0xFFFFFFFFL)   // FAT[1]
        writeChain(fat, bitmapFirstCluster, bitmapClusters)
        writeChain(fat, upcaseFirstCluster, upcaseClusters)
        writeChain(fat, rootFirstCluster, rootClusters)
        sectors.add((FAT_OFFSET_SEC.toLong() * SECTOR) to fat)

        // ================= 分配位图（簇 2）=================
        val bitmap = ByteArray(bitmapClusters * bytesPerCluster)
        // 标记已用簇 2..lastUsedCluster（bit (cluster-2)=1）。
        for (c in 2..lastUsedCluster) {
            val bit = (c - 2).toInt()
            bitmap[bit ushr 3] = (bitmap[bit ushr 3].toInt() or (1 shl (bit and 7))).toByte()
        }
        sectors.add(clusterOffset(bitmapFirstCluster, clusterHeapOffsetSec, sectorsPerCluster) to bitmap)

        // ================= upcase 表（簇 3..）=================
        val upcasePadded = ByteArray(upcaseClusters * bytesPerCluster)
        System.arraycopy(upcase, 0, upcasePadded, 0, upcase.size)
        sectors.add(clusterOffset(upcaseFirstCluster, clusterHeapOffsetSec, sectorsPerCluster) to upcasePadded)

        // ================= 根目录 =================
        val root = ByteArray(rootClusters * bytesPerCluster)
        var eo = 0
        // 卷标项 0x83（无卷标则 CharacterCount=0）。
        val label = volumeLabel.take(11)
        root[eo] = TYPE_LABEL.toByte()
        root[eo + 1] = label.length.toByte()
        for (i in label.indices) putU16(root, eo + 2 + i * 2, label[i].code)
        eo += ENTRY
        // 分配位图项 0x81。
        root[eo] = TYPE_BITMAP.toByte()
        root[eo + 1] = 0                                        // BitmapFlags：第一个位图
        putU32(root, eo + 20, bitmapFirstCluster)
        putU64(root, eo + 24, bitmapBytes)
        eo += ENTRY
        // upcase 表项 0x82。
        root[eo] = TYPE_UPCASE.toByte()
        putU32(root, eo + 4, upcaseChecksum)
        putU32(root, eo + 20, upcaseFirstCluster)
        putU64(root, eo + 24, upcase.size.toLong())
        // eo += ENTRY  之后全 0（0x00 = 目录结束）。
        sectors.add(clusterOffset(rootFirstCluster, clusterHeapOffsetSec, sectorsPerCluster) to root)

        return FatFormatter.FatImage(bytesPerSector = SECTOR, sectors = sectors)
    }

    // ---- 引导区（扇区 0..11，6144 字节）----
    private fun buildBootRegion(
        volumeLengthSec: Long,
        fatOffsetSec: Int,
        fatLengthSec: Int,
        clusterHeapOffsetSec: Int,
        clusterCount: Long,
        rootFirstCluster: Long,
        bytesPerSectorShift: Int,
        spcShift: Int,
    ): ByteArray {
        val region = ByteArray(12 * SECTOR)

        // ---- 扇区 0：主引导扇区（VBR）----
        region[0] = 0xEB.toByte(); region[1] = 0x76; region[2] = 0x90.toByte()  // JumpBoot
        val sig = "EXFAT   ".toByteArray(Charsets.US_ASCII)                       // 偏移 3，8 字节
        System.arraycopy(sig, 0, region, 3, 8)
        // 偏移 11..63 MustBeZero（已是 0）。
        putU64(region, 64, 0L)                          // PartitionOffset
        putU64(region, 72, volumeLengthSec)             // VolumeLength
        putU32(region, 80, fatOffsetSec.toLong())       // FatOffset
        putU32(region, 84, fatLengthSec.toLong())       // FatLength
        putU32(region, 88, clusterHeapOffsetSec.toLong())   // ClusterHeapOffset
        putU32(region, 92, clusterCount)                // ClusterCount
        putU32(region, 96, rootFirstCluster)            // FirstClusterOfRootDirectory
        putU32(region, 100, randomSerial())             // VolumeSerialNumber
        putU16(region, 104, 0x0100)                     // FileSystemRevision 1.00
        putU16(region, 106, 0)                          // VolumeFlags（校验和跳过）
        region[108] = bytesPerSectorShift.toByte()
        region[109] = spcShift.toByte()
        region[110] = 1                                 // NumberOfFats
        region[111] = 0x80.toByte()                     // DriveSelect
        region[112] = 0xFF.toByte()                     // PercentInUse=0xFF 未知，Windows 挂载重算（校验和跳过）
        // 偏移 113..119 Reserved（0）。BootCode 120..509（留 0）。
        putU16(region, 510, 0xAA55)                     // BootSignature

        // ---- 扇区 1..8：扩展引导扇区（末 4 字节 = 0xAA550000）----
        for (s in 1..8) {
            putU32(region, s * SECTOR + 508, 0xAA550000L)
        }
        // ---- 扇区 9：OEM 参数（全 0）；扇区 10：保留（全 0）----

        // ---- 扇区 11：主引导校验和 ----
        val checksum = bootChecksum(region, 11 * SECTOR)
        for (k in 0 until (SECTOR / 4)) {
            putU32(region, 11 * SECTOR + k * 4, checksum)
        }
        return region
    }

    /**
     * 主引导校验和（规范 3.4）：对前 [byteCount] 字节逐字节滚动 u32，
     * 跳过偏移 106/107（VolumeFlags）与 112（PercentInUse）。
     */
    private fun bootChecksum(data: ByteArray, byteCount: Int): Long {
        var c = 0L
        for (i in 0 until byteCount) {
            if (i == 106 || i == 107 || i == 112) continue
            c = (((c and 1L) shl 31) or (c ushr 1)) + (data[i].toInt() and 0xFF).toLong()
            c = c and 0xFFFFFFFFL
        }
        return c
    }

    /** upcase 表校验和（同滚动公式，不跳字节）。 */
    private fun tableChecksum(data: ByteArray): Long {
        var c = 0L
        for (b in data) {
            c = (((c and 1L) shl 31) or (c ushr 1)) + (b.toInt() and 0xFF).toLong()
            c = c and 0xFFFFFFFFL
        }
        return c
    }

    /**
     * 生成压缩 upcase 表：遍历 BMP 0..0xFFFF，逐码元取大写映射，恒等连续段用
     * 0xFFFF + count 压缩（与 [ExFatFileSystem] 的解压对称）。
     */
    private fun buildUpcaseCompressed(): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(v: Int) { out.write(v and 0xFF); out.write((v ushr 8) and 0xFF) }
        var idx = 0
        var run = 0
        while (idx <= 0xFFFF) {
            val up = Character.toUpperCase(idx.toChar()).code
            if (up == idx) {
                run++
            } else {
                if (run > 0) { u16(0xFFFF); u16(run); run = 0 }
                u16(up)
            }
            idx++
        }
        // 末尾恒等 run 不写（表覆盖不足处解析侧默认恒等）。
        return out.toByteArray()
    }

    /** 在 FAT 中写一条簇链：从 [first] 起连续 [count] 簇，末簇 EOC。 */
    private fun writeChain(fat: ByteArray, first: Long, count: Int) {
        for (i in 0 until count) {
            val cluster = first + i
            val next = if (i == count - 1) 0xFFFFFFFFL else cluster + 1
            putU32(fat, (cluster * 4).toInt(), next)
        }
    }

    /** 簇号到卷内逻辑字节偏移。 */
    private fun clusterOffset(cluster: Long, clusterHeapOffsetSec: Int, sectorsPerCluster: Int): Long =
        (clusterHeapOffsetSec.toLong() + (cluster - 2) * sectorsPerCluster) * SECTOR

    private fun randomSerial(): Long {
        val b = ByteArray(4)
        SecureRandom().nextBytes(b)
        return ((b[0].toInt() and 0xFF).toLong()) or ((b[1].toInt() and 0xFF).toLong() shl 8) or
            ((b[2].toInt() and 0xFF).toLong() shl 16) or ((b[3].toInt() and 0xFF).toLong() shl 24)
    }

    private fun putU16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v and 0xFF).toByte(); b[o + 1] = ((v shr 8) and 0xFF).toByte()
    }
    private fun putU32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v and 0xFF).toByte(); b[o + 1] = ((v shr 8) and 0xFF).toByte()
        b[o + 2] = ((v shr 16) and 0xFF).toByte(); b[o + 3] = ((v shr 24) and 0xFF).toByte()
    }
    private fun putU64(b: ByteArray, o: Int, v: Long) {
        for (k in 0 until 8) b[o + k] = ((v shr (8 * k)) and 0xFF).toByte()
    }
}
