package com.henglie.sealchest.fs

/**
 * FAT12 / FAT16 / FAT32 只读解析层。
 *
 * 全部读经 [VolumeReader]（解密 + 逻辑寻址），本层只见「卷内逻辑偏移」，不碰加密。
 * 只读：不实现写入、不改 FAT、不碰脏位。
 *
 * 解析路径：BPB → 判 FAT 类型（按簇总数）→ 定位 FAT 表 / 根目录 / 数据区 →
 * 按簇链遍历目录项，短名（8.3）+ VFAT 长名（LFN）合成条目。
 *
 * 线程不安全，与 [VolumeReader] 同一串行化域。
 */
class FatFileSystem private constructor(
    private val reader: VolumeReader,
    private val bpb: Bpb,
) : VolumeFs {

    override val fsType: String get() = when (bpb.fatType) {
        FatType.FAT12 -> "FAT12"
        FatType.FAT16 -> "FAT16"
        FatType.FAT32 -> "FAT32"
    }
    override val volumeLabel: String get() = bpb.volumeLabel
    val fatType: FatType get() = bpb.fatType

    // ---- 布局（全部以「逻辑字节偏移」为单位，reader 直接吃）----
    private val bytesPerSector = bpb.bytesPerSector
    private val bytesPerCluster = bpb.bytesPerSector * bpb.sectorsPerCluster
    private val fatStartOffset = bpb.reservedSectors.toLong() * bytesPerSector
    private val fatBytes = bpb.fatSizeSectors * bytesPerSector.toLong()
    private val rootDirStartOffset =
        fatStartOffset + bpb.numFats.toLong() * fatBytes
    /** FAT12/16 根目录占固定扇区数；FAT32 为 0（根目录是普通簇链）。 */
    private val rootDirBytes = bpb.rootEntryCount.toLong() * 32
    private val rootDirSectors =
        ((rootDirBytes + bytesPerSector - 1) / bytesPerSector) * bytesPerSector
    /** 数据区（簇 2 起）逻辑偏移。 */
    private val dataStartOffset = rootDirStartOffset + rootDirSectors

    /** 簇号 → 卷内逻辑偏移。簇编号从 2 起。 */
    private fun clusterToOffset(cluster: Long): Long =
        dataStartOffset + (cluster - 2) * bytesPerCluster

    /** FAT 结束标记：≥ 该值即链尾。按类型不同。 */
    private val eocMin: Long = when (bpb.fatType) {
        FatType.FAT12 -> 0x0FF8
        FatType.FAT16 -> 0xFFF8
        FatType.FAT32 -> 0x0FFFFFF8
    }

    /** 读 FAT 表项：给定簇号返回下一簇号（或 ≥ [eocMin] 表示链尾）。 */
    private fun nextCluster(cluster: Long): Long = when (bpb.fatType) {
        FatType.FAT12 -> {
            // 每项 12 bit，两项共 3 字节交错。
            val idx = cluster + (cluster / 2)          // *1.5
            val off = fatStartOffset + idx
            val b = reader.read(off, 2)
            val raw = (b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8)
            (if (cluster and 1L == 0L) raw and 0x0FFF else (raw shr 4) and 0x0FFF).toLong()
        }
        FatType.FAT16 -> {
            val off = fatStartOffset + cluster * 2
            val b = reader.read(off, 2)
            ((b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8)).toLong()
        }
        FatType.FAT32 -> {
            val off = fatStartOffset + cluster * 4
            val b = reader.read(off, 4)
            (((b[0].toInt() and 0xFF).toLong()) or
                ((b[1].toInt() and 0xFF).toLong() shl 8) or
                ((b[2].toInt() and 0xFF).toLong() shl 16) or
                ((b[3].toInt() and 0xFF).toLong() shl 24)) and 0x0FFFFFFFL
        }
    }

    /** 收集一条簇链的全部簇号。带上限防坏 FAT 死循环。 */
    private fun clusterChain(first: Long): List<Long> {
        if (first < 2) return emptyList()
        val out = ArrayList<Long>()
        var c = first
        val maxClusters = bpb.countOfClusters + 2
        while (c in 2 until eocMin && out.size <= maxClusters) {
            out.add(c)
            c = nextCluster(c)
            if (c < 2) break     // 0/1 非法，防御性截断
        }
        return out
    }

    /** 读整条簇链的原始字节（[limit] < 0 读全部；否则读够 limit 即止）。 */
    private fun readChain(first: Long, limit: Long = -1): ByteArray {
        val chain = clusterChain(first)
        val total = if (limit >= 0) limit else chain.size.toLong() * bytesPerCluster
        val out = ByteArray(total.toInt().coerceAtLeast(0))
        var written = 0
        for (c in chain) {
            if (written >= out.size) break
            val chunk = minOf(bytesPerCluster, out.size - written)
            reader.read(clusterToOffset(c), out, written, chunk)
            written += chunk
        }
        return out
    }

    // ---------------- 目录遍历 ----------------

    /** 列根目录。 */
    override fun listRoot(): List<FsEntry> = when (bpb.fatType) {
        FatType.FAT32 -> listDirEntries(readChain(bpb.rootCluster))
        else -> {
            // FAT12/16 根目录是定长连续区，不走簇链。
            val buf = reader.read(rootDirStartOffset, rootDirBytes.toInt())
            listDirEntries(buf)
        }
    }

    /**
     * 列某子目录（按其起始簇）。
     * [firstCluster] < 2 表示根目录——统一 [VolumeFs] 契约（0 = 各 FS 的根），
     * 写路径的 [findEntry]/[openDir] 早已按 <2 特判根，读路径这里必须对齐，
     * 否则 listDir(0) 走 readChain(0) 得空链，调用方看不到刚写进根的条目。
     */
    override fun listDir(firstCluster: Long): List<FsEntry> =
        if (firstCluster < 2) listRoot() else listDirEntries(readChain(firstCluster))

    /**
     * 解析一段目录区字节为条目列表。处理 VFAT 长名（LFN）合成、
     * 删除项（0xE5）、卷标 / 系统项过滤、0x00 结束标记。
     */
    private fun listDirEntries(dir: ByteArray): List<FsEntry> {
        val out = ArrayList<FsEntry>()
        val lfnParts = ArrayList<String>()   // 逆序累积的 LFN 片段
        var i = 0
        while (i + 32 <= dir.size) {
            val first = dir[i].toInt() and 0xFF
            if (first == 0x00) break                    // 目录结束
            if (first == 0xE5) { i += 32; lfnParts.clear(); continue }  // 已删除

            val attr = dir[i + 11].toInt() and 0xFF
            if (attr and 0x0F == 0x0F) {                // LFN 项
                lfnParts.add(parseLfnPart(dir, i))
                i += 32
                continue
            }
            if (attr and 0x08 != 0) {                   // 卷标项，跳过（含 FAT32 根卷标）
                i += 32; lfnParts.clear(); continue
            }

            val name = if (lfnParts.isNotEmpty()) {
                // LFN 片段是逆序存的（seq 从大到小写入），拼回来要反转。
                lfnParts.reversed().joinToString("").trimEnd('￿', ' ', '\u0000')
            } else {
                parseShortName(dir, i)
            }
            lfnParts.clear()

            val isDir = attr and 0x10 != 0
            val firstCluster = readFirstCluster(dir, i)
            val size = readU32(dir, i + 28)
            val mtime = parseDosDateTime(dir, i)

            // 跳过 . 和 ..（SAF 用绝对簇号导航，不需要）。隐藏 / 系统文件仍列出：
            // 取证用途要看到全部内容，不做过滤。
            if (name == "." || name == "..") { i += 32; continue }
            out.add(FsEntry(name, isDir, if (isDir) 0 else size, firstCluster, mtime))
            i += 32
        }
        return out
    }

    /** 读目录项的起始簇（高 16 位在 0x14，低 16 位在 0x1A）。 */
    private fun readFirstCluster(dir: ByteArray, off: Int): Long {
        val lo = (dir[off + 26].toInt() and 0xFF) or ((dir[off + 27].toInt() and 0xFF) shl 8)
        val hi = if (bpb.fatType == FatType.FAT32)
            (dir[off + 20].toInt() and 0xFF) or ((dir[off + 21].toInt() and 0xFF) shl 8)
        else 0
        return ((hi.toLong() shl 16) or lo.toLong())
    }

    private fun readU32(b: ByteArray, off: Int): Long =
        ((b[off].toInt() and 0xFF).toLong()) or
            ((b[off + 1].toInt() and 0xFF).toLong() shl 8) or
            ((b[off + 2].toInt() and 0xFF).toLong() shl 16) or
            ((b[off + 3].toInt() and 0xFF).toLong() shl 24)

    /** 解析 8.3 短名为可读串。 */
    private fun parseShortName(dir: ByteArray, off: Int): String {
        val base = StringBuilder()
        for (k in 0 until 8) {
            val c = dir[off + k].toInt() and 0xFF
            if (c == 0x20) break
            base.append(if (k == 0 && c == 0x05) 0xE5.toChar() else c.toChar())
        }
        val ext = StringBuilder()
        for (k in 8 until 11) {
            val c = dir[off + k].toInt() and 0xFF
            if (c == 0x20) break
            ext.append(c.toChar())
        }
        return if (ext.isEmpty()) base.toString() else "$base.$ext"
    }

    /** 解析单个 LFN 项的 13 个 UTF-16 字符（偏移 1..10 / 14..25 / 28..31）。 */
    private fun parseLfnPart(dir: ByteArray, off: Int): String {
        val sb = StringBuilder(13)
        val idx = intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)
        for (p in idx) {
            val c = (dir[off + p].toInt() and 0xFF) or ((dir[off + p + 1].toInt() and 0xFF) shl 8)
            if (c == 0x0000 || c == 0xFFFF) break
            sb.append(c.toChar())
        }
        return sb.toString()
    }

    /** DOS 日期(0x18) + 时间(0x16) → epoch 毫秒。 */
    private fun parseDosDateTime(dir: ByteArray, off: Int): Long {
        val time = (dir[off + 22].toInt() and 0xFF) or ((dir[off + 23].toInt() and 0xFF) shl 8)
        val date = (dir[off + 24].toInt() and 0xFF) or ((dir[off + 25].toInt() and 0xFF) shl 8)
        if (date == 0) return 0
        val year = 1980 + ((date shr 9) and 0x7F)
        val month = (date shr 5) and 0x0F
        val day = date and 0x1F
        val hour = (time shr 11) and 0x1F
        val min = (time shr 5) and 0x3F
        val sec = (time and 0x1F) * 2
        return try {
            val cal = java.util.Calendar.getInstance()
            cal.clear()
            cal.set(year, (month - 1).coerceIn(0, 11), day.coerceIn(1, 31), hour, min, sec)
            cal.timeInMillis
        } catch (_: Exception) {
            0
        }
    }

    // ---------------- 文件读取 ----------------

    /**
     * 读某文件 [start] 起 [length] 字节。[firstCluster]/[fileSize] 来自 [FsEntry]。
     * 越界自动裁剪。返回实际读到的字节。
     */
    override fun readFile(firstCluster: Long, fileSize: Long, start: Long, length: Int): ByteArray {
        if (start >= fileSize || firstCluster < 2) return ByteArray(0)
        val end = minOf(start + length, fileSize)
        val want = (end - start).toInt()
        if (want <= 0) return ByteArray(0)

        val out = ByteArray(want)
        val chain = clusterChain(firstCluster)
        // 定位起始簇在链中的下标 + 簇内偏移。
        var skip = start
        var chainIdx = (skip / bytesPerCluster).toInt()
        var within = (skip % bytesPerCluster).toInt()
        var written = 0
        while (written < want && chainIdx < chain.size) {
            val c = chain[chainIdx]
            val chunk = minOf(bytesPerCluster - within, want - written)
            reader.read(clusterToOffset(c) + within, out, written, chunk)
            written += chunk
            within = 0
            chainIdx++
        }
        return out
    }

    // ---------------- FAT 表写入（读改写簇链，双份回写）----------------
    //
    // 全部经 [VolumeReader.write]（512B 单元 read-modify-write + XTS 加密回写）。
    // 本区不 flush —— 落盘由写入门面层（MountManager）在一批结构改动后统一 force，
    // 减少半写窗口。红线：FAT 有 numFats（通常 2）份副本，每次改必须逐份写，
    // 否则桌面 VeraCrypt / chkdsk 判定两份不一致而报错。

    /** FAT 项数上界：最大合法簇号 = [Bpb.countOfClusters] + 1（簇号从 2 起）。 */
    private val maxCluster: Long = bpb.countOfClusters.toLong() + 1

    /** 写入用的链尾标记（EOC）。读侧 [eocMin] 是「判尾阈值」，这里是「实际写值」。 */
    private val eocMark: Long = when (bpb.fatType) {
        FatType.FAT12 -> 0x0FFFL
        FatType.FAT16 -> 0xFFFFL
        FatType.FAT32 -> 0x0FFFFFFFL
    }

    /**
     * 写单簇 FAT 表项到「某一份」FAT（[fatBase] = 该副本起始逻辑偏移）。
     * 三种类型各自 read-modify-write，保住不属于本项的位：
     *  - FAT12：12bit 交错，两项共 3 字节，改一项须保另半字节。
     *  - FAT32：表项仅低 28bit 有效，高 4bit 为保留位，回写时原样保留。
     */
    private fun writeFatEntry(fatBase: Long, cluster: Long, value: Long) {
        when (bpb.fatType) {
            FatType.FAT12 -> {
                val idx = cluster + (cluster / 2)          // *1.5
                val off = fatBase + idx
                val b = reader.read(off, 2)
                var raw = (b[0].toInt() and 0xFF) or ((b[1].toInt() and 0xFF) shl 8)
                val v = (value and 0x0FFF).toInt()
                raw = if (cluster and 1L == 0L) {
                    (raw and 0xF000) or v                  // 偶簇：低 12 位
                } else {
                    (raw and 0x000F) or (v shl 4)          // 奇簇：高 12 位
                }
                b[0] = (raw and 0xFF).toByte()
                b[1] = ((raw shr 8) and 0xFF).toByte()
                reader.write(off, b, 0, 2)
            }
            FatType.FAT16 -> {
                val off = fatBase + cluster * 2
                val v = value and 0xFFFF
                val b = byteArrayOf((v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte())
                reader.write(off, b, 0, 2)
            }
            FatType.FAT32 -> {
                val off = fatBase + cluster * 4
                val b = reader.read(off, 4)
                val old = readU32(b, 0)
                val merged = (old and 0xF0000000L) or (value and 0x0FFFFFFFL)
                b[0] = (merged and 0xFF).toByte()
                b[1] = ((merged shr 8) and 0xFF).toByte()
                b[2] = ((merged shr 16) and 0xFF).toByte()
                b[3] = ((merged shr 24) and 0xFF).toByte()
                reader.write(off, b, 0, 4)
            }
        }
    }

    /**
     * 设置簇 [cluster] 的 FAT 表项为 [value]（下一簇号 / EOC / 0 释放）。
     * **两份（numFats）FAT 都写**。[cluster] 必须 ≥ 2（0/1 是保留项，不可改）。
     */
    fun setNextCluster(cluster: Long, value: Long) {
        require(cluster in 2..maxCluster) { "簇号越界: $cluster (合法 2..$maxCluster)" }
        for (n in 0 until bpb.numFats) {
            writeFatEntry(fatStartOffset + n * fatBytes, cluster, value)
        }
    }

    /**
     * 分配一个空闲簇：扫 FAT 找首个值为 0 的簇，标记为 EOC 并返回其簇号。
     * 无空闲簇返回 -1。分配后该簇即一条独立单簇链的尾（EOC），调用方
     * 负责把它挂进目标链 / 目录项，否则会成为孤立簇（空间泄漏，非损坏）。
     */
    fun allocCluster(): Long {
        var c = 2L
        while (c <= maxCluster) {
            if (nextCluster(c) == 0L) {
                setNextCluster(c, eocMark)
                return c
            }
            c++
        }
        return -1L
    }

    /**
     * 外层卷已用数据区的物理上界（卷内逻辑字节偏移），供 C2 隐藏卷创建算安全区。
     *
     * 扫整张 FAT 找**最高的已占用簇**（表项非 0 = 已分配，含数据链尾与坏簇），
     * 返回该簇之后第一个字节的卷内逻辑偏移（= [clusterToOffset](最高簇 + 1)）。
     * 隐藏卷数据区只要整体落在此偏移**之后**，就不会覆盖外层卷任何已用簇——这是
     * 「读外层 FAT 算安全区」写保护的地基（对齐桌面 VeraCrypt 挂外层卷时的隐藏卷保护，
     * 但我们是创建期一次性静态检查，非运行时拦截）。
     *
     * 全空（无任何已用簇）时返回数据区起始 [dataStartOffset]——隐藏卷可用满整个数据区。
     * 注意：返回的是**卷内逻辑偏移**（VolumeReader 语义，0 = 数据区首字节前的卷头之后），
     * 调用方换算容器文件绝对偏移时需叠加外层卷的 encryptedAreaStart。
     */
    override fun usedDataAreaUpperBound(): Long {
        var highest = 1L   // 低于首个合法簇（2），表示「未发现已用簇」
        var c = 2L
        while (c <= maxCluster) {
            if (nextCluster(c) != 0L) highest = c
            c++
        }
        // 无已用簇：整个数据区可用，上界 = 数据区起点。
        if (highest < 2L) return dataStartOffset
        // 最高已用簇之后第一个字节 = 下一簇的起始偏移。
        return clusterToOffset(highest + 1)
    }

    /**
     * 回收整条簇链：从 [first] 起沿链把每个簇的 FAT 项置 0。
     * **先收集整链再逐簇清零**（复用只读 [clusterChain]），避免边遍历边改断链。
     * [first] < 2 直接返回（空链 / 非法）。
     */
    fun freeChain(first: Long) {
        if (first < 2) return
        val chain = clusterChain(first)
        for (c in chain) setNextCluster(c, 0)
    }

    /**
     * FAT 表写往返自检（零净变更）：分配一个空闲簇 → 读回应为 EOC →
     * 释放 → 读回应为 0。测完该簇复原为 0（且整 512B 单元加密回原密文，
     * 容器字节零净变更）。无空闲簇则 [FatWriteSelfTest.skipped]。
     *
     * 注意：全程真写 channel（未 flush、未 force）。逻辑上完全复原，但为
     * 稳妥仅供带真实容器时点验，不在生产路径自动跑。
     */
    fun selfTestFatTable(): FatWriteSelfTest {
        val c = allocCluster()
        if (c < 2) return FatWriteSelfTest(skipped = true, allocEoc = false, freedZero = false)
        val afterAlloc = nextCluster(c)                 // 期望 ≥ eocMin（EOC）
        val allocEoc = afterAlloc >= eocMin
        freeChain(c)
        val afterFree = nextCluster(c)                  // 期望 == 0
        val freedZero = afterFree == 0L
        return FatWriteSelfTest(skipped = false, allocEoc = allocEoc, freedZero = freedZero)
    }

    /** [selfTestFatTable] 结果。[passed] 全真才算 FAT 写方向可用。 */
    data class FatWriteSelfTest(
        val skipped: Boolean,
        val allocEoc: Boolean,
        val freedZero: Boolean,
    ) {
        val passed: Boolean get() = !skipped && allocEoc && freedZero
    }

    // ---------------- 目录项写入（增删 + VFAT 长名生成）----------------
    //
    // 全部经 [VolumeReader.write]（512B 单元 read-modify-write + XTS 加密回写）。
    // 红线：目录项写错桌面 VeraCrypt 会显示乱条目或拒挂。LFN 项逆序写
    // （物理顺序 seq=N|0x40 在前 → seq=1 → 短名项最后），与读侧 [listDirEntries]
    // 的「顺序累积 LFN 再 reversed」严格对应。短名 11 字节 + LFN 校验和须
    // 符合 FAT 规范，否则 Windows / VC 无法合成长名。
    //
    // 目录分两种：FAT12/16 根目录是定长连续区（[rootDirStartOffset]，不可扩簇，
    // 满则失败）；FAT32 根目录 + 所有子目录是簇链（可经 [allocCluster] 扩簇）。
    // [dirFirstCluster] < 2 表示根目录（FAT32 取 [bpb.rootCluster] 的链）。
    //
    // 32 字节目录项不会跨簇（32 整除 bytesPerSector，而 bytesPerCluster 是其倍数），
    // 故连续多项可跨簇存储——写回时逐项映射逻辑偏移即可。

    /** 目录项属性位。 */
    private val ATTR_DIRECTORY = 0x10
    private val ATTR_ARCHIVE = 0x20
    private val ATTR_LFN = 0x0F

    /** LFN 项 13 个 UTF-16 字符的字节偏移（1-10 / 14-25 / 28-31）。 */
    private val LFN_CHAR_OFFSETS = intArrayOf(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)

    /** 目录区内存镜像 + 簇链，写操作的工作集。 */
    private class DirContext(
        val buf: ByteArray,
        val chain: List<Long>,
        val isFixed: Boolean,
    )

    /** 该目录是否为定长根目录（FAT12/16，不可扩簇）。 */
    private fun isFixedRootDir(dirFirstCluster: Long): Boolean =
        dirFirstCluster < 2 && bpb.fatType != FatType.FAT32

    /** 打开目录：读全部目录字节到内存，保留簇链供偏移映射。 */
    private fun openDir(dirFirstCluster: Long): DirContext {
        if (isFixedRootDir(dirFirstCluster)) {
            return DirContext(
                reader.read(rootDirStartOffset, rootDirBytes.toInt()),
                emptyList(), true,
            )
        }
        val first = if (dirFirstCluster < 2) bpb.rootCluster else dirFirstCluster
        return DirContext(readChain(first), clusterChain(first), false)
    }

    /** 目录 buf 下标 → 卷内逻辑偏移（逐项映射，跨簇安全）。 */
    private fun dirBufIndexToLogical(ctx: DirContext, idx: Int): Long {
        if (ctx.isFixed) return rootDirStartOffset + idx
        val clusterIdx = idx / bytesPerCluster
        val within = idx % bytesPerCluster
        if (clusterIdx >= ctx.chain.size) return -1L   // 防御性
        return clusterToOffset(ctx.chain[clusterIdx]) + within
    }

    // ---- 短名（8.3）生成 + 消歧 ----

    /** 字符是否可出现在 8.3 短名里（点也排除，点仅作 base/ext 分隔概念）。 */
    private fun isShortNameChar(c: Char): Boolean {
        if (c.code < 0x20) return false
        return when (c) {
            '"', '*', '/', ':', '<', '>', '?', '\\', '|', '.' -> false
            else -> true
        }
    }

    /** 名字是否需要 LFN（不满足纯 8.3 大写合法名时为真）。 */
    private fun needsLfn(name: String): Boolean {
        val dot = name.lastIndexOf('.')
        val base: String
        val ext: String
        if (dot > 0 && dot < name.length - 1) {
            base = name.substring(0, dot); ext = name.substring(dot + 1)
        } else if (dot <= 0) {
            base = name; ext = ""
        } else {
            return true   // 以点开头或结尾
        }
        if (base.isEmpty() || base.length > 8) return true
        if (ext.length > 3) return true
        fun ok(s: String) = s == s.uppercase() && s.all { isShortNameChar(it) }
        return !ok(base) || (ext.isNotEmpty() && !ok(ext))
    }

    /** 收集目录中所有现有短名（11 字节 ASCII 串），供消歧查重。 */
    private fun collectShortNames(ctx: DirContext): HashSet<String> {
        val set = HashSet<String>()
        val buf = ctx.buf
        var i = 0
        while (i + 32 <= buf.size) {
            val first = buf[i].toInt() and 0xFF
            if (first == 0x00) break
            if (first != 0xE5) {
                val attr = buf[i + 11].toInt() and 0xFF
                if (attr and 0x0F != 0x0F && attr and 0x08 == 0) {
                    set.add(String(buf, i, 11, Charsets.US_ASCII))
                }
            }
            i += 32
        }
        return set
    }

    /**
     * 为 [name] 生成 8.3 短名（11 字节，空格 0x20 填充）。
     * [needLfn] 时用 `~N` 消歧（base 前 6 + `~N`，N 从 1 递增直到 [existing] 无冲突）；
     * 否则直接填合法 8.3。非法字符转 `_`，统一大写。
     */
    private fun makeShortName(existing: HashSet<String>, name: String, needLfn: Boolean): ByteArray {
        val dot = name.lastIndexOf('.')
        val rawBase: String
        val rawExt: String
        if (dot > 0 && dot < name.length - 1) {
            rawBase = name.substring(0, dot); rawExt = name.substring(dot + 1)
        } else if (dot <= 0) {
            rawBase = name; rawExt = ""
        } else {
            rawBase = name.substring(0, dot); rawExt = ""
        }
        fun clean(s: String) =
            s.uppercase().map { if (isShortNameChar(it)) it else '_' }.joinToString("")
        val cleanBase = clean(rawBase)
        val cleanExt = clean(rawExt)

        val short11 = ByteArray(11) { 0x20 }
        if (!needLfn) {
            for (i in cleanBase.indices.take(8)) short11[i] = cleanBase[i].code.toByte()
            for (i in cleanExt.indices.take(3)) short11[8 + i] = cleanExt[i].code.toByte()
            return short11
        }
        var n = 1
        while (n < 1000000) {
            // `~N` 消歧：base 段固定 8 字节，须为 `~N` 留位——保留 cleanBase 前
            // (8 - "~N".length) 字符再拼 `~N`，从头保留、给后缀留位。这样 N≥10 时
            // `~N` 不会被尾部截断（如 `BATCH_~10` 不会退化成 `BATCH_~1` 而与 `~1`
            // 永久撞名），符合 FAT 短名生成惯例。
            val suffix = "~$n"
            val keep = (8 - suffix.length).coerceAtLeast(1)
            val base = cleanBase.take(keep) + suffix
            for (i in 0 until 11) short11[i] = 0x20
            for (i in base.indices) short11[i] = base[i].code.toByte()
            for (i in cleanExt.indices.take(3)) short11[8 + i] = cleanExt[i].code.toByte()
            if (!existing.contains(String(short11, Charsets.US_ASCII))) return short11
            n++
        }
        throw IllegalStateException("短名消歧耗尽: $name")
    }

    /** 11 字节短名 → 可读串（与读侧 [parseShortName] 同逻辑）。 */
    private fun shortNameToString(s11: ByteArray): String {
        val base = StringBuilder()
        for (k in 0 until 8) {
            val c = s11[k].toInt() and 0xFF
            if (c == 0x20) break
            base.append(if (k == 0 && c == 0x05) 0xE5.toChar() else c.toChar())
        }
        val ext = StringBuilder()
        for (k in 8 until 11) {
            val c = s11[k].toInt() and 0xFF
            if (c == 0x20) break
            ext.append(c.toChar())
        }
        return if (ext.isEmpty()) base.toString() else "$base.$ext"
    }

    // ---- LFN 校验和 + 项生成 ----

    /** VFAT LFN 校验和：短名 11 字节的 rotate-right-add（FAT 规范标准式）。 */
    private fun lfnChecksum(short11: ByteArray): Int {
        var sum = 0
        for (i in 0 until 11) {
            sum = (((sum and 1) shl 7) + (sum shr 1) + (short11[i].toInt() and 0xFF)) and 0xFF
        }
        return sum
    }

    /**
     * 构造 [name] 的 LFN 项列表（已逆序：seq=N|0x40 在前 → seq=1 在后）。
     * 字符流 = name + 0x0000 终止符，按每 13 UTF-16 字符分块，末块不足补 0xFFFF。
     * 项数 = ceil((name.length + 1) / 13)，保证有终止符位置。
     */
    private fun buildLfnEntries(name: String, checksum: Int): List<ByteArray> {
        val chars = name.toCharArray()
        val numEntries = (chars.size + 1 + 12) / 13   // ceil((len+1)/13)
        val entries = ArrayList<ByteArray>(numEntries)
        var pos = 0
        for (seq in 1..numEntries) {
            val e = ByteArray(32) { 0xFF.toByte() }    // 字符位默认 0xFFFF
            val isLast = seq == numEntries
            e[0] = (if (isLast) seq or 0x40 else seq).toByte()
            e[11] = ATTR_LFN.toByte()
            e[12] = 0
            e[13] = checksum.toByte()
            e[26] = 0; e[27] = 0
            for (k in LFN_CHAR_OFFSETS.indices) {
                val c: Char = when {
                    pos < chars.size -> chars[pos]
                    pos == chars.size -> '\u0000'       // 终止符
                    else -> '\uFFFF'                    // 填充
                }
                pos++
                val off = LFN_CHAR_OFFSETS[k]
                e[off] = (c.code and 0xFF).toByte()
                e[off + 1] = ((c.code shr 8) and 0xFF).toByte()
            }
            entries.add(e)
        }
        return entries.reversed()   // 逆序：seq 大在前
    }

    /** 构造 32 字节短名目录项。 */
    private fun buildShortEntry(
        short11: ByteArray, isDir: Boolean, firstCluster: Long, size: Long,
    ): ByteArray {
        val e = ByteArray(32)
        System.arraycopy(short11, 0, e, 0, 11)
        e[11] = (if (isDir) ATTR_DIRECTORY else ATTR_ARCHIVE).toByte()
        // 起始簇高 16 位（FAT32，偏移 20-21）
        val hi = (firstCluster shr 16).toInt()
        e[20] = (hi and 0xFF).toByte()
        e[21] = ((hi shr 8) and 0xFF).toByte()
        // 写时间/日期（偏移 22-25），填当前时间更真实
        val cal = java.util.Calendar.getInstance()
        val fatTime = ((cal.get(java.util.Calendar.HOUR_OF_DAY) shl 11) or
            (cal.get(java.util.Calendar.MINUTE) shl 5) or
            (cal.get(java.util.Calendar.SECOND) / 2))
        val fatDate = (((cal.get(java.util.Calendar.YEAR) - 1980) shl 9) or
            ((cal.get(java.util.Calendar.MONTH) + 1) shl 5) or
            cal.get(java.util.Calendar.DAY_OF_MONTH))
        e[22] = (fatTime and 0xFF).toByte(); e[23] = ((fatTime shr 8) and 0xFF).toByte()
        e[24] = (fatDate and 0xFF).toByte(); e[25] = ((fatDate shr 8) and 0xFF).toByte()
        // 起始簇低 16 位（偏移 26-27）
        val lo = firstCluster.toInt()
        e[26] = (lo and 0xFF).toByte(); e[27] = ((lo shr 8) and 0xFF).toByte()
        // 文件大小（偏移 28-31，目录 = 0）
        val sz = if (isDir) 0L else size
        e[28] = (sz and 0xFF).toByte()
        e[29] = ((sz shr 8) and 0xFF).toByte()
        e[30] = ((sz shr 16) and 0xFF).toByte()
        e[31] = ((sz shr 24) and 0xFF).toByte()
        return e
    }

    // ---- 槽位查找 + 删除标记 ----

    /**
     * 在目录 buf 中找连续 [slotsNeeded] 个空闲槽位（0x00 或 0xE5）。
     * 返回起始下标，找不到返回 -1。可跨簇（buf 是多簇拼接的连续数组）。
     */
    private fun findFreeSlots(buf: ByteArray, slotsNeeded: Int): Int {
        var runStart = -1
        var runLen = 0
        var i = 0
        while (i + 32 <= buf.size) {
            val first = buf[i].toInt() and 0xFF
            if (first == 0x00 || first == 0xE5) {
                if (runStart < 0) { runStart = i; runLen = 0 }
                runLen++
                if (runLen >= slotsNeeded) return runStart
            } else {
                runStart = -1; runLen = 0
            }
            i += 32
        }
        return -1
    }

    /** 把目录项首字节置 0xE5（删除标记），读-改-写 32 字节。 */
    private fun markDeleted(ctx: DirContext, bufIndex: Int) {
        val logical = dirBufIndexToLogical(ctx, bufIndex)
        val item = reader.read(logical, 32)
        item[0] = 0xE5.toByte()
        reader.write(logical, item, 0, 32)
    }

    // ---- 条目定位（removeEntry / update 共用）----

    private class EntryLoc(val shortPos: Int, val lfnPositions: List<Int>)

    /**
     * 定位匹配 [name] 的条目（长名或短名任一匹配）。
     * 返回短名项 buf 下标 + 前导 LFN 项 buf 下标列表。找不到返回 null。
     */
    private fun locateEntry(ctx: DirContext, name: String): EntryLoc? {
        val buf = ctx.buf
        val lfnPositions = ArrayList<Int>()
        var i = 0
        while (i + 32 <= buf.size) {
            val first = buf[i].toInt() and 0xFF
            if (first == 0x00) break
            if (first == 0xE5) { lfnPositions.clear(); i += 32; continue }
            val attr = buf[i + 11].toInt() and 0xFF
            if (attr and 0x0F == 0x0F) { lfnPositions.add(i); i += 32; continue }
            if (attr and 0x08 != 0) { lfnPositions.clear(); i += 32; continue }
            val sn = parseShortName(buf, i)
            val ln = if (lfnPositions.isNotEmpty()) {
                lfnPositions.map { parseLfnPart(buf, it) }
                    .reversed().joinToString("")
                    .trimEnd('\uFFFF', ' ', '\u0000')
            } else sn
            if (ln == name || sn == name) return EntryLoc(i, ArrayList(lfnPositions))
            lfnPositions.clear()
            i += 32
        }
        return null
    }

    // ---- 公开 API ----

    /**
     * 在 [dirFirstCluster]（< 2 = 根目录）指定的目录里新增一个条目。
     * 自动生成 8.3 短名（含 `~N` 消歧）+ VFAT 长名项（需 LFN 时）。
     * 目录满时：簇链目录经 [allocCluster] 扩簇；FAT12/16 根目录不可扩，失败。
     *
     * [firstCluster] = 新条目的起始簇（空文件/空目录传 0）。
     * [size] = 文件字节数（目录传 0，忽略）。
     *
     * 返回 [AddEntryResult]：[AddEntryResult.ok] 成功时 [AddEntryResult.shortName] 为生成的 8.3 名。
     */
    fun addEntry(
        dirFirstCluster: Long, name: String, isDir: Boolean,
        firstCluster: Long, size: Long,
    ): AddEntryResult {
        val needLfn = needsLfn(name)
        val ctx = openDir(dirFirstCluster)
        val existing = collectShortNames(ctx)
        val short11 = makeShortName(existing, name, needLfn)
        val checksum = lfnChecksum(short11)
        val lfnEntries = if (needLfn) buildLfnEntries(name, checksum) else emptyList()
        val slotsNeeded = lfnEntries.size + 1

        // 单簇容量检查（防超长名撑爆最小簇）
        if (slotsNeeded > bytesPerCluster / 32) {
            return AddEntryResult(false, short11, "条目槽位超单簇容量")
        }

        val idx = findFreeSlots(ctx.buf, slotsNeeded)
        val baseLogical: Long
        val useBuf: Boolean
        if (idx >= 0) {
            baseLogical = 0L; useBuf = true
        } else {
            if (ctx.isFixed) return AddEntryResult(false, short11, "根目录已满（FAT12/16 不可扩）")
            if (ctx.chain.isEmpty()) return AddEntryResult(false, short11, "目录簇链空")
            val newC = allocCluster()
            if (newC < 2) return AddEntryResult(false, short11, "无空闲簇")
            setNextCluster(ctx.chain.last(), newC)
            // 新簇清零（全 0x00 = 目录结束标记）
            reader.write(clusterToOffset(newC), ByteArray(bytesPerCluster))
            baseLogical = clusterToOffset(newC); useBuf = false
        }

        fun itemLogical(k: Int): Long =
            if (useBuf) dirBufIndexToLogical(ctx, idx + k * 32) else baseLogical + k * 32L

        // LFN 项（逆序，seq 大在前）→ 短名项
        for (k in lfnEntries.indices) {
            reader.write(itemLogical(k), lfnEntries[k], 0, 32)
        }
        val shortEntry = buildShortEntry(short11, isDir, firstCluster, size)
        reader.write(itemLogical(lfnEntries.size), shortEntry, 0, 32)

        return AddEntryResult(true, short11, null)
    }

    /**
     * 删除匹配 [name]（长名或短名）的条目：短名项 + 前导 LFN 项首字节全置 0xE5。
     * 返回是否找到并删除。
     */
    fun removeEntry(dirFirstCluster: Long, name: String): Boolean {
        val ctx = openDir(dirFirstCluster)
        val loc = locateEntry(ctx, name) ?: return false
        for (pos in loc.lfnPositions) markDeleted(ctx, pos)
        markDeleted(ctx, loc.shortPos)
        return true
    }

    /** 更新匹配 [name] 条目的文件大小（偏移 28-31）。 */
    fun updateEntrySize(dirFirstCluster: Long, name: String, newSize: Long): Boolean {
        val ctx = openDir(dirFirstCluster)
        val loc = locateEntry(ctx, name) ?: return false
        val off = dirBufIndexToLogical(ctx, loc.shortPos + 28)
        reader.write(off, byteArrayOf(
            (newSize and 0xFF).toByte(),
            ((newSize shr 8) and 0xFF).toByte(),
            ((newSize shr 16) and 0xFF).toByte(),
            ((newSize shr 24) and 0xFF).toByte(),
        ), 0, 4)
        return true
    }

    /** 更新匹配 [name] 条目的起始簇（偏移 20-21 高 16 位 + 26-27 低 16 位）。 */
    fun updateEntryFirstCluster(dirFirstCluster: Long, name: String, newFirstCluster: Long): Boolean {
        val ctx = openDir(dirFirstCluster)
        val loc = locateEntry(ctx, name) ?: return false
        val lo = newFirstCluster.toInt()
        reader.write(dirBufIndexToLogical(ctx, loc.shortPos + 26), byteArrayOf(
            (lo and 0xFF).toByte(), ((lo shr 8) and 0xFF).toByte(),
        ), 0, 2)
        if (bpb.fatType == FatType.FAT32) {
            val hi = (newFirstCluster shr 16).toInt()
            reader.write(dirBufIndexToLogical(ctx, loc.shortPos + 20), byteArrayOf(
                (hi and 0xFF).toByte(), ((hi shr 8) and 0xFF).toByte(),
            ), 0, 2)
        }
        return true
    }

    /**
     * 目录项写往返自检（零净变更）：在根目录加条目 → 列目录能看到 → 删 → 列不到。
     * 两轮：① 纯 8.3 名（无 LFN）② 长名含小写（触发 LFN 生成 + 长名回读匹配）。
     * 全程真写 channel（未 flush、未 force），逻辑复原（删除后目录项置 0xE5）。
     */
    fun selfTestDirEntries(): DirWriteSelfTest {
        // ① 短名
        val sn = "SEALCHST.TST"
        val r1 = addEntry(0, sn, isDir = false, firstCluster = 0, size = 0)
        if (!r1.ok) return DirWriteSelfTest(false, false, false, false, false, false, false, "短名 addEntry 失败: ${r1.reason}")
        val addVisible = listRoot().any { it.name == sn }
        val rem1 = removeEntry(0, sn)
        val afterGone = listRoot().none { it.name == sn }
        if (!rem1 || !afterGone) return DirWriteSelfTest(true, addVisible, rem1, afterGone, false, false, false, "短名删除失败")

        // ② 长名（含小写，触发 LFN）
        val ln = "SealchestSelfTest.txt"
        val r2 = addEntry(0, ln, isDir = false, firstCluster = 0, size = 0)
        if (!r2.ok) return DirWriteSelfTest(true, addVisible, true, true, false, false, false, "长名 addEntry 失败: ${r2.reason}")
        val lfnMatch = listRoot().any { it.name == ln }
        val rem2 = removeEntry(0, ln)
        val lfnGone = listRoot().none { it.name == ln }

        return DirWriteSelfTest(
            true, addVisible, true, true,
            r2.ok, lfnMatch, rem2 && lfnGone,
            if (lfnMatch && lfnGone) null else "长名校验失败",
        )
    }

    /** [addEntry] 结果。 */
    data class AddEntryResult(
        val ok: Boolean,
        val shortName11: ByteArray,
        val reason: String? = null,
    ) {
        /** 生成的 8.3 短名可读串（如 `SEALCH~1.TXT`）。 */
        val shortName: String get() = with(shortName11) {
            val base = StringBuilder()
            for (k in 0 until 8) { val c = this[k].toInt() and 0xFF; if (c == 0x20) break; base.append(if (k == 0 && c == 0x05) 0xE5.toChar() else c.toChar()) }
            val ext = StringBuilder()
            for (k in 8 until 11) { val c = this[k].toInt() and 0xFF; if (c == 0x20) break; ext.append(c.toChar()) }
            if (ext.isEmpty()) base.toString() else "$base.$ext"
        }
    }

    /** [selfTestDirEntries] 结果。 */
    data class DirWriteSelfTest(
        val addOk: Boolean,
        val addVisible: Boolean,
        val removeOk: Boolean,
        val afterRemoveGone: Boolean,
        val lfnAddOk: Boolean,
        val lfnNameMatch: Boolean,
        val lfnRemoveOk: Boolean,
        val reason: String? = null,
    ) {
        val passed: Boolean get() = addOk && addVisible && removeOk && afterRemoveGone &&
            lfnAddOk && lfnNameMatch && lfnRemoveOk
    }

    // ================== FAT 写入门面 ==================
    // 把 FAT 表 + 目录项底层能力组装成用户级操作。事务顺序统一为
    // 「先写数据簇 → 再挂 FAT 链 → 最后写目录项」：任一步崩溃都不会留下「目录项
    // 指向未分配簇」的悬挂引用，最坏只丢一条未挂链的空闲簇（下次 chkdsk 可回收）。
    // 本区不碰底层位操作，只编排。调用方须在 MountManager 锁内串行调用。

    /** 在目录 [dirFirstCluster]（<2 表示根目录）里按名查条目；找不到返回 null。 */
    private fun findEntry(dirFirstCluster: Long, name: String): FsEntry? {
        val list = if (dirFirstCluster < 2) listRoot() else listDir(dirFirstCluster)
        return list.firstOrNull { it.name == name }
    }

    /**
     * 让 FAT32 FSInfo 的「空闲簇计数 / 下一空闲簇提示」失效（置 0xFFFFFFFF = unknown）。
     *
     * 为什么不精确维护：写入门面改了 FAT 表却没同步 FSInfo 的缓存计数，桌面 VC / chkdsk
     * 会报「空闲空间不符、已修正」。FAT32 规范明确 0xFFFFFFFF 表示「未知，请重算」——
     * 把两个字段置哨兵值，OS 下次挂载自行扫 FAT 重算，绝不会报不符。这比维护精确计数
     * 稳得多（少一处易错的双写点）。
     *
     * 仅 FAT32 且 BPB 声明了合法 FSInfo 扇区时执行；写前校验三处签名，任一不符则不动
     * （防误写非 FSInfo 扇区）。FAT12/16 无 FSInfo，直接返回。**调用方负责随后 flush。**
     */
    override fun invalidateFsInfo() {
        if (bpb.fatType != FatType.FAT32 || bpb.fsInfoSector <= 0) return
        val secOff = bpb.fsInfoSector.toLong() * bytesPerSector
        val buf = reader.read(secOff, bytesPerSector)
        // 三签名：lead 0x41615252 @0、struct 0x61417272 @484、trail 0xAA550000 @508。
        fun u32(o: Int) = (buf[o].toInt() and 0xFF).toLong() or
            ((buf[o + 1].toInt() and 0xFF).toLong() shl 8) or
            ((buf[o + 2].toInt() and 0xFF).toLong() shl 16) or
            ((buf[o + 3].toInt() and 0xFF).toLong() shl 24)
        if (u32(0) != 0x41615252L || u32(484) != 0x61417272L || u32(508) != 0xAA550000L) return
        // FSI_Free_Count @488、FSI_Nxt_Free @492 均置 0xFFFFFFFF（unknown）。
        for (o in intArrayOf(488, 492)) {
            buf[o] = 0xFF.toByte(); buf[o + 1] = 0xFF.toByte()
            buf[o + 2] = 0xFF.toByte(); buf[o + 3] = 0xFF.toByte()
        }
        reader.write(secOff, buf, 0, bytesPerSector)
    }

    /**
     * 分配一条能容纳 [byteCount] 字节的簇链并写入 [data]，返回首簇号；
     * [byteCount]=0 返回 0（空文件不占簇，符合 FAT 语义）。中途无空闲簇则
     * 回滚已分配的簇（freeChain）并返回 -1，不留半条链。
     */
    private fun allocAndWriteChain(data: ByteArray): Long {
        if (data.isEmpty()) return 0L
        val needClusters = ((data.size + bytesPerCluster - 1) / bytesPerCluster)
        val clusters = ArrayList<Long>(needClusters)
        for (i in 0 until needClusters) {
            val c = allocCluster()               // 标 EOC 占位，防同一簇被重复分配
            if (c < 2) {                          // 空间不足：回滚已分配簇，抛 VolumeFullException
                for (a in clusters) setNextCluster(a, 0L)
                throw VolumeFullException()
            }
            clusters.add(c)
        }
        // 挂链：前一簇指向后一簇，末簇保持 allocCluster 标好的 EOC。
        for (i in 0 until clusters.size - 1) setNextCluster(clusters[i], clusters[i + 1])
        // 写数据：逐簇填，末簇尾部补零，防残留旧明文片段。
        var off = 0
        for (c in clusters) {
            val chunk = minOf(bytesPerCluster, data.size - off)
            if (chunk < bytesPerCluster) {
                // 末簇：数据 + 尾部补零，防覆写小文件后末簇尾残留旧明文片段，
                // 对齐写入门面整簇清零策略。size 之外不读，但清零避免信息泄漏与脏数据。
                val full = ByteArray(bytesPerCluster)
                System.arraycopy(data, off, full, 0, chunk)
                reader.write(clusterToOffset(c), full, 0, bytesPerCluster)
            } else {
                reader.write(clusterToOffset(c), data, off, chunk)
            }
            off += chunk
        }
        return clusters[0]
    }

    /**
     * 新建文件：把 [bytes] 写进目录 [dirFirstCluster]（<2=根）下名为 [name] 的新文件。
     * 同名已存在则失败（调用方先删或改用 [overwriteFile]）。
     * 事务序：先写数据簇 → 再建目录项。返回 true 成功。**调用方负责随后 flush。**
     */
    override fun writeFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        if (findEntry(dirFirstCluster, name) != null) return false
        val firstCluster = allocAndWriteChain(bytes)
        if (firstCluster < 0) return false
        val r = addEntry(dirFirstCluster, name, isDir = false, firstCluster = firstCluster, size = bytes.size.toLong())
        if (!r.ok) {
            // 目录项没建成：回收刚写的数据簇，不留孤链。
            if (firstCluster >= 2) freeChain(firstCluster)
            return false
        }
        return true
    }

    /**
     * 删除文件：先回收数据簇链，再抹目录项。顺序反过来（先抹目录项）也安全，
     * 但先回收簇能保证「目录里还能看到时簇已释放」不成立——统一先簇后目录项，
     * 与新建的「先簇后目录项」对称。返回 true 表示确实删了一个条目。
     *
     * 拒绝目录：删目录要递归清空子项，否则 freeChain 掉目录簇链会留下孤儿链 +
     * 子项数据丢失。目录删属二期，本版只删文件，遇目录返回 false（防御门面被误用）。
     */
    override fun deleteFile(dirFirstCluster: Long, name: String): Boolean {
        val e = findEntry(dirFirstCluster, name) ?: return false
        if (e.isDirectory) return false
        if (e.firstCluster >= 2) freeChain(e.firstCluster)
        return removeEntry(dirFirstCluster, name)
    }

    /**
     * 原地覆写文件内容。两种情形：
     *   - 新内容簇数 == 旧簇数：直接逐簇写，不动 FAT / 目录项（除 size）。
     *   - 簇数变化：先分配新链（失败则完全不动旧数据）→ 成功再释放旧链 →
     *     更新目录项 firstCluster + size。**顺序是「先建后拆」，中途失败旧数据完好，
     *     绝不能反过来先释放旧链——那样分配失败就丢了原文件。**
     * [bytes] 为空则内容清零（释放旧链、firstCluster 置 0、size=0）。
     * 返回 true 成功；文件不存在返回 false。**调用方负责随后 flush。**
     */
    override fun overwriteFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        val e = findEntry(dirFirstCluster, name) ?: return false
        if (e.isDirectory) return false

        val oldClusters = if (e.firstCluster >= 2) clusterChain(e.firstCluster).size else 0
        val newClusters = (bytes.size + bytesPerCluster - 1) / bytesPerCluster

        if (newClusters == oldClusters && oldClusters > 0) {
            // 簇数不变：原地逐簇写，只更新 size（内容变、布局不变，最省、最稳）。
            // M2 修复：新内容比旧短但簇数不变时，尾簇 [bytes.size, bytesPerCluster) 区间必须补零，
            //   否则旧明文残留（信息残留，非结构损坏）。故整簇对齐写、尾簇补零，对齐 allocAndWriteChain。
            val chain = clusterChain(e.firstCluster)
            var off = 0
            for (c in chain) {
                val chunk = minOf(bytesPerCluster, bytes.size - off)
                if (chunk <= 0) break
                val block = if (chunk == bytesPerCluster) bytes.copyOfRange(off, off + chunk)
                            else ByteArray(bytesPerCluster).also { System.arraycopy(bytes, off, it, 0, chunk) }
                reader.write(clusterToOffset(c), block, 0, bytesPerCluster)
                off += chunk
            }
            updateEntrySize(dirFirstCluster, name, bytes.size.toLong())
            return true
        }

        // 簇数变化：先分配新链（失败则完全不动旧数据），成功再释放旧链、改目录项。
        val newFirst = allocAndWriteChain(bytes)
        if (newFirst < 0) return false
        if (e.firstCluster >= 2) freeChain(e.firstCluster)
        updateEntryFirstCluster(dirFirstCluster, name, newFirst)
        updateEntrySize(dirFirstCluster, name, bytes.size.toLong())
        return true
    }

    // ================== 目录操作（rename / mkdir / move / rmdir）==================
    // 纯目录项 + FAT 编排，复用底层 FAT 表 / 目录项 / 写入门面，不碰底层位。红线：一律「先建后拆」
    // 保原子性，拿不准的复杂场景返回 false/0 不动盘。调用方须在 MountManager 锁内
    // 串行调用，并负责随后 flush。

    /**
     * 重命名：同目录内把 [oldName] 改名为 [newName]，数据簇不动。
     * 读旧项 firstCluster/size/isDir → newName 已存在则 false → addEntry 建新项
     * 复用同一 firstCluster → removeEntry 抹旧项（先建后拆，建新失败不拆旧）。
     * 短名 `~N` 消歧由 makeShortName 依现存短名集自动避让，不会撞旧项。
     */
    override fun rename(dirFirstCluster: Long, oldName: String, newName: String): Boolean {
        if (oldName == newName) return true
        val src = findEntry(dirFirstCluster, oldName) ?: return false
        if (findEntry(dirFirstCluster, newName) != null) return false
        val r = addEntry(dirFirstCluster, newName, src.isDirectory, src.firstCluster, src.size)
        if (!r.ok) return false
        // 建新成功才拆旧。同目录改名父目录不变，无需动 `..`。
        removeEntry(dirFirstCluster, oldName)
        return true
    }

    /**
     * 新建目录：allocCluster 分配一簇 → 整簇清零（全 0x00 = 目录结束标记）→
     * 写 `.`/`..` 两条 8.3 短名项 → 父目录 addEntry。成功返新目录首簇（≥2）；
     * 失败返 0（对齐 VolumeFs 约定）。addEntry 失败 freeChain 回滚新簇，不留孤链。
     * `..` 指向父目录簇；父为根目录（[dirFirstCluster] < 2）则写 0（FAT 规范：
     * 根目录无簇号语义，`..` 一律 0，含 FAT32 根，OS 见 0 即解为根）。
     */
    override fun mkdir(dirFirstCluster: Long, name: String): Long {
        if (findEntry(dirFirstCluster, name) != null) return 0L
        val newCluster = allocCluster()
        if (newCluster < 2) return 0L
        reader.write(clusterToOffset(newCluster), ByteArray(bytesPerCluster))   // 整簇清零
        val dotDotCluster = if (dirFirstCluster < 2) 0L else dirFirstCluster
        val dot = ByteArray(11) { 0x20 }.also { it[0] = 0x2E }                  // ".          "
        val dotDot = ByteArray(11) { 0x20 }.also { it[0] = 0x2E; it[1] = 0x2E } // "..         "
        val base = clusterToOffset(newCluster)
        reader.write(base, buildShortEntry(dot, isDir = true, firstCluster = newCluster, size = 0), 0, 32)
        reader.write(base + 32, buildShortEntry(dotDot, isDir = true, firstCluster = dotDotCluster, size = 0), 0, 32)
        val r = addEntry(dirFirstCluster, name, isDir = true, firstCluster = newCluster, size = 0)
        if (!r.ok) {
            freeChain(newCluster)   // 目录项没建成：回收新簇，不留孤链
            return 0L
        }
        return newCluster
    }

    /**
     * 同卷移动：把 [srcDirFirstCluster] 下的 [name] 移到 [dstDirFirstCluster]，
     * 数据簇不搬。读源项 → 目标 addEntry 复用 firstCluster/size → 源 removeEntry
     * （先建后拆）。目标已存在同名则 false。若移动的是目录，其 `..` 项 firstCluster
     * 更新为新父簇（新父为根则 0）——read-modify-write 该目录首簇里的 `..` 项。
     */
    override fun move(srcDirFirstCluster: Long, name: String, dstDirFirstCluster: Long): Boolean {
        if (srcDirFirstCluster == dstDirFirstCluster) return true
        val src = findEntry(srcDirFirstCluster, name) ?: return false
        if (findEntry(dstDirFirstCluster, name) != null) return false
        val r = addEntry(dstDirFirstCluster, name, src.isDirectory, src.firstCluster, src.size)
        if (!r.ok) return false
        removeEntry(srcDirFirstCluster, name)   // 建新成功才拆旧
        // 移动的是目录：更新其 `..` 指向新父（新父为根则 0）。
        if (src.isDirectory && src.firstCluster >= 2) {
            val newParent = if (dstDirFirstCluster < 2) 0L else dstDirFirstCluster
            updateEntryFirstCluster(src.firstCluster, "..", newParent)
        }
        return true
    }

    /**
     * 删目录：locateEntry 找到，非目录 false。判空 = 除 `.`/`..` 外无有效项
     * （listDir 已过滤 0x00 结束/0xE5 删除/卷标/LFN/`.`/`..`，其结果空即空目录）。
     * 空：freeChain(目录首簇) + removeEntry。非空：[recursive]=false 拒绝返 false（安全）；
     * true 先递归删全部子项（文件 deleteFile / 子目录 rmdir(recursive=true)）再删自身。
     * 递归删的是 listDir 的快照，逐个按名删互不干扰（FAT 同目录不允许重名）。
     */
    override fun rmdir(dirFirstCluster: Long, name: String, recursive: Boolean): Boolean {
        val e = findEntry(dirFirstCluster, name) ?: return false
        if (!e.isDirectory) return false
        val dirCluster = e.firstCluster
        val children = if (dirCluster >= 2) listDir(dirCluster) else emptyList()
        if (children.isNotEmpty()) {
            if (!recursive) return false
            for (child in children) {
                val ok = if (child.isDirectory) rmdir(dirCluster, child.name, recursive = true)
                         else deleteFile(dirCluster, child.name)
                if (!ok) return false   // 子项删失败即中止，不硬删父目录
            }
        }
        // 已空（或递归清空）：先回收目录簇链，再抹父目录里的目录项。
        if (dirCluster >= 2) freeChain(dirCluster)
        return removeEntry(dirFirstCluster, name)
    }

    companion object {
        /**
         * 从已开卷的 [reader] 解析 BPB 并建 FAT 文件系统。
         * 非 FAT / 无法识别时抛 [IllegalArgumentException]。
         */
        fun mount(reader: VolumeReader): FatFileSystem {
            val boot = reader.read(0, 512)
            val bpb = Bpb.parse(boot)
            return FatFileSystem(reader, bpb)
        }
    }
}
