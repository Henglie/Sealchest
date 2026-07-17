package com.henglie.sealchest.fs

/**
 * exFAT 文件系统解析层（当前只读，写方向见 TODO）。
 *
 * 全部读经 [VolumeReader]（解密 + 逻辑寻址），本层只见「卷内逻辑偏移」，不碰加密。
 * 与 FAT 走同一套 [VolumeFs] 接口，故 [MountManager] / SAF / UI 零感知底层是 FAT 还是 exFAT。
 *
 * exFAT 与 FAT 的关键差异：
 *  - 无 BPB，引导扇区偏移 64 起固定字段（见 [ExFatBoot]）。
 *  - FAT 表项 32 位；但文件可「连续分配」（流扩展 NoFatChain 位置 1），此时不走 FAT 链，
 *    簇号连续递增，靠数据长度算簇数。读簇链必须先看这个位。
 *  - 目录项 32 字节定长，成组：0x85 文件项 + 0xC0 流扩展 + 1..N 个 0xC1 文件名项。
 *    名字是 UTF-16LE，每个 0xC1 项承载 15 个字符。
 *  - 卷标在根目录 0x83 项（非引导扇区）。
 *
 * 线程不安全，与 [VolumeReader] 同一串行化域。
 */
class ExFatFileSystem private constructor(
    private val reader: VolumeReader,
    private val boot: ExFatBoot,
) : VolumeFs {

    override val fsType: String get() = "exFAT"
    override val volumeLabel: String get() = boot.volumeLabel

    private val bytesPerCluster = boot.bytesPerCluster

    // ---- 元数据（mount 时扫根目录回填：分配位图 0x81 + upcase 表 0x82）----
    /** 分配位图首簇 / 字节长度 / 簇链。位 i（bit）对应簇 i+2，置 1 = 已用。 */
    private var bitmapFirstCluster = 0L
    private var bitmapDataLength = 0L
    private var bitmapChain: List<Long> = emptyList()
    /** upcase 表：下标 = UTF-16 码元，值 = 其大写映射。null = 未读到，回退 ASCII 大写。 */
    private var upcaseTable: CharArray? = null

    // ---- 目录项类型 ----

    // ---- FAT 表读 ----

    /** 读 FAT 表项：簇 [cluster] 的下一簇。 */
    private fun nextFatEntry(cluster: Long): Long {
        val off = boot.fatByteOffset + cluster * 4
        val b = reader.read(off, 4)
        return ((b[0].toInt() and 0xFF).toLong()) or
            ((b[1].toInt() and 0xFF).toLong() shl 8) or
            ((b[2].toInt() and 0xFF).toLong() shl 16) or
            ((b[3].toInt() and 0xFF).toLong() shl 24)
    }

    /**
     * 求簇链。[noFatChain]=true 时（连续分配）用 [dataLength] 算簇数、簇号连续递增，
     * 不读 FAT；否则顺 FAT 链走到 EOC。
     */
    private fun clusterChain(first: Long, noFatChain: Boolean, dataLength: Long): List<Long> {
        if (first < 2) return emptyList()
        val out = ArrayList<Long>()
        if (noFatChain) {
            val n = ((dataLength + bytesPerCluster - 1) / bytesPerCluster).coerceAtLeast(0)
            var c = first
            var i = 0L
            while (i < n) { out.add(c); c++; i++ }
            return out
        }
        var c = first
        val maxClusters = boot.clusterCount + 2
        var guard = 0L
        while (c in 2 until maxClusters) {
            out.add(c)
            val next = nextFatEntry(c)
            if (next >= EOC || next == BAD_CLUSTER || next < 2) break
            c = next
            if (++guard > maxClusters) break   // 环路保护
        }
        return out
    }

    // ---- 读簇链内容 ----

    /** 读整条簇链的前 [limit] 字节（limit<0 = 全部）。 */
    private fun readChain(chain: List<Long>, limit: Long): ByteArray {
        val total = if (limit >= 0) limit else chain.size.toLong() * bytesPerCluster
        val out = ByteArray(total.toInt().coerceAtLeast(0))
        var written = 0
        for (c in chain) {
            if (written >= out.size) break
            val chunk = minOf(bytesPerCluster, out.size - written)
            val data = reader.read(boot.clusterToOffset(c), chunk)
            System.arraycopy(data, 0, out, written, chunk)
            written += chunk
        }
        return out
    }

    // ---- 目录解析 ----

    /**
     * 遍历目录（首簇 [dirFirstCluster]），返回条目。根目录传 [ExFatBoot.rootCluster]。
     * 根目录始终走 FAT 链（NoFatChain 仅用于文件/子目录的流扩展）。
     */
    private fun parseDir(dirFirstCluster: Long): List<FsEntry> {
        val chain = clusterChain(dirFirstCluster, noFatChain = false, dataLength = 0)
        if (chain.isEmpty()) return emptyList()
        val buf = readChain(chain, -1)
        return parseDirBuf(buf)
    }

    private fun parseDirBuf(buf: ByteArray): List<FsEntry> {
        val out = ArrayList<FsEntry>()
        var i = 0
        while (i + ENTRY_SIZE <= buf.size) {
            val type = buf[i].toInt() and 0xFF
            if (type == 0x00) break            // EndOfDirectory
            if (type and 0x80 == 0) { i += ENTRY_SIZE; continue }  // 未用（InUse 位为 0）

            if (type == TYPE_FILE) {
                val parsed = parseFileEntryGroup(buf, i)
                if (parsed != null) {
                    out.add(parsed.entry)
                    i += parsed.consumedEntries * ENTRY_SIZE
                    continue
                }
            }
            i += ENTRY_SIZE
        }
        return out
    }

    private class FileGroup(val entry: FsEntry, val consumedEntries: Int)

    /**
     * 从 0x85 文件项起解析一组（0x85 + 0xC0 + N×0xC1）。[base] 指向 0x85 项。
     * 组内项数 = 0x85 项偏移 1 的 SecondaryCount + 1。
     */
    private fun parseFileEntryGroup(buf: ByteArray, base: Int): FileGroup? {
        val secondaryCount = buf[base + 1].toInt() and 0xFF
        val totalEntries = secondaryCount + 1
        if (base + totalEntries * ENTRY_SIZE > buf.size) return null

        val attr = u16(buf, base + 4)
        val isDir = (attr and ATTR_DIRECTORY) != 0
        val mtime = parseTimestamp(buf, base + 8)   // LastModified（0x85 偏移 8）

        // 次项：第一个应是 0xC0 流扩展。
        val streamOff = base + ENTRY_SIZE
        if ((buf[streamOff].toInt() and 0xFF) != TYPE_STREAM_EXT) return null
        val flags = buf[streamOff + 1].toInt() and 0xFF
        val noFatChain = (flags and FLAG_NO_FAT_CHAIN) != 0
        val nameLength = buf[streamOff + 3].toInt() and 0xFF   // 名字字符数
        val firstCluster = u32(buf, streamOff + 20)
        val dataLength = u64(buf, streamOff + 24)

        // 之后是 N 个 0xC1 文件名项，拼 UTF-16LE。
        val sb = StringBuilder(nameLength)
        var remaining = nameLength
        var ei = streamOff + ENTRY_SIZE
        while (remaining > 0 && ei + ENTRY_SIZE <= buf.size) {
            if ((buf[ei].toInt() and 0xFF) != TYPE_FILE_NAME) break
            var k = 0
            while (k < 15 && remaining > 0) {
                val ch = u16(buf, ei + 2 + k * 2)
                sb.append(ch.toChar())
                k++; remaining--
            }
            ei += ENTRY_SIZE
        }

        val name = sb.toString()
        if (name.isEmpty()) return null
        val entry = FsEntry(
            name = name,
            isDirectory = isDir,
            size = if (isDir) 0L else dataLength,
            firstCluster = firstCluster,
            lastModified = mtime,
        )
        // 把 noFatChain / dataLength 记进缓存，读文件时避免重解析。
        chainHint[firstCluster] = ChainHint(noFatChain, dataLength)
        return FileGroup(entry, totalEntries)
    }

    /** 首簇 → (noFatChain, dataLength) 提示，parseDir 时填，readFile 时用。 */
    private val chainHint = HashMap<Long, ChainHint>()
    private class ChainHint(val noFatChain: Boolean, val dataLength: Long)

    /** exFAT 时间戳（DOS 风格 32 位，偏移见规范）→ 毫秒。 */
    private fun parseTimestamp(buf: ByteArray, off: Int): Long {
        val ts = u32(buf, off)
        val sec = ((ts and 0x1F) * 2).toInt()
        val min = ((ts shr 5) and 0x3F).toInt()
        val hour = ((ts shr 11) and 0x1F).toInt()
        val day = ((ts shr 16) and 0x1F).toInt()
        val month = ((ts shr 21) and 0x0F).toInt()
        val year = 1980 + ((ts shr 25) and 0x7F).toInt()
        return runCatching {
            val cal = java.util.Calendar.getInstance()
            cal.clear()
            cal.set(year, (month - 1).coerceIn(0, 11), day.coerceIn(1, 31), hour, min, sec)
            cal.timeInMillis
        }.getOrDefault(0L)
    }

    // ---- mount 时扫根目录：回填卷标 + 分配位图(0x81) + upcase 表(0x82) ----
    // 位图/upcase 是 exFAT 写方向的地基：分配簇要查/改位图，算文件名 NameHash 要 upcase。
    private fun scanRootMeta() {
        val chain = clusterChain(boot.rootCluster, noFatChain = false, dataLength = 0)
        if (chain.isEmpty()) return
        val buf = readChain(chain, -1)
        var i = 0
        while (i + ENTRY_SIZE <= buf.size) {
            val type = buf[i].toInt() and 0xFF
            if (type == 0x00) break
            when (type) {
                TYPE_VOLUME_LABEL -> {
                    val n = buf[i + 1].toInt() and 0xFF
                    val sb = StringBuilder(n)
                    var k = 0
                    while (k < n && k < 11) { sb.append(u16(buf, i + 2 + k * 2).toChar()); k++ }
                    boot.volumeLabel = sb.toString()
                }
                TYPE_ALLOCATION_BITMAP -> {
                    // 0x81：偏移 20 首簇(u32)、偏移 24 数据长度(u64)。第一个位图（BitmapFlags bit0=0）。
                    val bmpFlags = buf[i + 1].toInt() and 0xFF
                    if (bmpFlags and 0x01 == 0) {   // 0 = 第一个 FAT 对应的位图
                        bitmapFirstCluster = u32(buf, i + 20)
                        bitmapDataLength = u64(buf, i + 24)
                    }
                }
                TYPE_UPCASE_TABLE -> {
                    // 0x82：偏移 20 首簇、偏移 24 数据长度。表是 u16[]，下标=码元，值=大写映射。
                    val first = u32(buf, i + 20)
                    val len = u64(buf, i + 24)
                    upcaseTable = readUpcaseTable(first, len)
                }
            }
            i += ENTRY_SIZE
        }
        if (bitmapFirstCluster >= 2) {
            bitmapChain = clusterChain(bitmapFirstCluster, noFatChain = false, dataLength = 0)
        }
    }

    /** 读 upcase 表（压缩格式：值 0xFFFF 后跟一个 count 表示恒等映射的连续区段）。 */
    private fun readUpcaseTable(first: Long, dataLength: Long): CharArray {
        val table = CharArray(0x10000) { it.toChar() }   // 默认恒等
        if (first < 2 || dataLength <= 0) return table
        val chain = clusterChain(first, noFatChain = false, dataLength = dataLength)
        val raw = readChain(chain, dataLength)
        var idx = 0            // 目标码元下标
        var p = 0              // raw 字节游标
        while (p + 1 < raw.size && idx < 0x10000) {
            val v = u16(raw, p); p += 2
            if (v == 0xFFFF && p + 1 < raw.size) {
                // 压缩标记：下一个 u16 = 恒等映射的字符数，跳过。
                val count = u16(raw, p); p += 2
                idx += count
            } else {
                table[idx] = v.toChar()
                idx++
            }
        }
        return table
    }

    /** 单个 UTF-16 码元的大写映射（无表则回退 ASCII）。 */
    private fun upcase(c: Char): Char {
        val t = upcaseTable
        return if (t != null) t[c.code and 0xFFFF] else if (c in 'a'..'z') c - 32 else c
    }

    // ---- VolumeFs 接口实现 ----

    override fun listRoot(): List<FsEntry> = parseDir(boot.rootCluster)

    override fun listDir(firstCluster: Long): List<FsEntry> =
        parseDir(if (firstCluster < 2) boot.rootCluster else firstCluster)

    override fun readFile(firstCluster: Long, fileSize: Long, start: Long, length: Int): ByteArray {
        if (firstCluster < 2 || fileSize <= 0) return ByteArray(0)
        val end = minOf(start + length, fileSize)
        val want = (end - start).toInt()
        if (want <= 0) return ByteArray(0)

        // chainHint 由 parseDir 填充；但 SAF openDocument 按 docId 直接读、不经 listDir，
        // 此时 hint 缺失。若退化为 noFatChain=false 走 FAT 链，桌面 VC 连续分配的 NoFatChain
        // 大文件（FAT 项为 0）会在首簇 nextFatEntry 返回 0 时立即 break，只读到首簇 →
        // 从第二簇起全读成零（读出错误数据）。故 hint 缺失时探测首簇 FAT 项推断布局。
        val noFatChain = chainHint[firstCluster]?.noFatChain ?: run {
            // hint 缺失（SAF openDocument 直接按 docId 定位，不经 listDir）：探测首簇 FAT 项。
            // NoFatChain 连续分配文件的 FAT 项为 0（不使用 FAT）；真 FAT 链首簇指向有效后继(>=2)或 EOC。
            if (firstCluster < 2) false else {
                val firstFat = nextFatEntry(firstCluster)
                firstFat < 2 && firstFat != EOC
            }
        }
        val chain = clusterChain(firstCluster, noFatChain, fileSize)

        val out = ByteArray(want)
        var skip = start
        var chainIdx = (skip / bytesPerCluster).toInt()
        var within = (skip % bytesPerCluster).toInt()
        var written = 0
        while (written < want && chainIdx < chain.size) {
            val c = chain[chainIdx]
            val chunk = minOf(bytesPerCluster - within, want - written)
            val data = reader.read(boot.clusterToOffset(c) + within, chunk)
            System.arraycopy(data, 0, out, written, chunk)
            written += chunk
            within = 0
            chainIdx++
        }
        return out
    }

    override fun usedDataAreaUpperBound(): Long {
        // 隐藏卷创建算安全区用：扫分配位图找最高已用簇 → 其数据区末字节逻辑偏移。
        // 位图不可用时保守返回簇堆末尾（全区，最安全）。
        if (bitmapChain.isEmpty()) {
            return boot.clusterHeapByteOffset + boot.clusterCount * bytesPerCluster
        }
        var highest = 1L   // < 2 表示未发现已用簇
        var c = 2L
        val max = boot.clusterCount + 2
        while (c < max) {
            if (isClusterUsed(c)) highest = c
            c++
        }
        if (highest < 2) return boot.clusterHeapByteOffset  // 空盘：数据区起点
        // 最高已用簇之后一簇的起点 = 已用区末字节逻辑上界。
        return boot.clusterToOffset(highest + 1)
    }

    // ---- 分配位图：位 (cluster-2) 对应簇，置 1 = 已用 ----

    /** 位图中簇 [cluster] 的 (字节逻辑偏移, 位掩码)。 */
    private fun bitmapBitLocation(cluster: Long): Pair<Long, Int> {
        val bitIndex = cluster - 2
        val byteIndex = bitIndex / 8
        val bitInByte = (bitIndex % 8).toInt()
        // 位图数据在其簇链上连续排布：第 byteIndex 字节落在链的哪一簇内。
        val chainIdx = (byteIndex / bytesPerCluster).toInt()
        val within = byteIndex % bytesPerCluster
        val cl = bitmapChain[chainIdx]
        return Pair(boot.clusterToOffset(cl) + within, 1 shl bitInByte)
    }

    private fun isClusterUsed(cluster: Long): Boolean {
        if (cluster < 2 || bitmapChain.isEmpty()) return true  // 未知视为已用，绝不误分配
        val (off, mask) = bitmapBitLocation(cluster)
        val b = reader.read(off, 1)[0].toInt() and 0xFF
        return (b and mask) != 0
    }

    private fun setClusterBit(cluster: Long, used: Boolean) {
        if (cluster < 2 || bitmapChain.isEmpty()) return
        val (off, mask) = bitmapBitLocation(cluster)
        val b = (reader.read(off, 1)[0].toInt() and 0xFF)
        val nb = if (used) (b or mask) else (b and mask.inv())
        reader.write(off, byteArrayOf(nb.toByte()), 0, 1)
    }

    // ---- FAT 表写 ----

    private fun writeFatEntry(cluster: Long, value: Long) {
        val off = boot.fatByteOffset + cluster * 4
        val b = byteArrayOf(
            (value and 0xFF).toByte(),
            ((value shr 8) and 0xFF).toByte(),
            ((value shr 16) and 0xFF).toByte(),
            ((value shr 24) and 0xFF).toByte(),
        )
        reader.write(off, b, 0, 4)
    }

    /** 分配一个空闲簇：位图找 0 位 → 置 1 → 返回簇号。无空闲返回 0。 */
    private fun allocCluster(): Long {
        if (bitmapChain.isEmpty()) return 0L
        var c = 2L
        val max = boot.clusterCount + 2
        while (c < max) {
            if (!isClusterUsed(c)) {
                setClusterBit(c, true)
                return c
            }
            c++
        }
        return 0L
    }

    /**
     * 分配 [bytes] 所需簇并写入数据，建 FAT 链（末簇 EOC）。返回首簇；失败返回 0（已回滚）。
     * 走 FAT 链（非 NoFatChain），永远合法，免连续空闲区搜索。
     */
    /**
     * 分配 [need] 个连续空闲簇（W3，NoFatChain 大文件用）。返回首簇；无连续段返回 -1（不占位图）。
     * 成功则置位图全部 need 位。NoFatChain 不写 FAT 链，簇号连续即定位。
     */
    private fun allocContiguous(need: Int): Long {
        if (bitmapChain.isEmpty() || need <= 0) return -1L
        val max = boot.clusterCount + 2
        var runStart = -1L
        var runLen = 0
        var c = 2L
        while (c < max) {
            if (!isClusterUsed(c)) {
                if (runStart < 0) runStart = c
                runLen++
                if (runLen >= need) {
                    for (k in 0 until need) setClusterBit(runStart + k, true)
                    return runStart
                }
            } else {
                runStart = -1; runLen = 0
            }
            c++
        }
        return -1L
    }

    private fun allocAndWriteChain(bytes: ByteArray): Long {
        if (bytes.isEmpty()) return 0L
        val need = ((bytes.size + bytesPerCluster - 1) / bytesPerCluster)
        val clusters = ArrayList<Long>(need)
        for (k in 0 until need) {
            val c = allocCluster()
            if (c < 2) { clusters.forEach { setClusterBit(it, false) }; throw VolumeFullException() }  // 回滚 + W18
            clusters.add(c)
        }
        // 写 FAT 链：每簇指向下一簇，末簇 EOC。
        for (k in clusters.indices) {
            writeFatEntry(clusters[k], if (k == clusters.size - 1) EOC else clusters[k + 1])
        }
        // 写数据。
        var off = 0
        for (c in clusters) {
            val chunk = minOf(bytesPerCluster, bytes.size - off)
            val block = if (chunk == bytesPerCluster) bytes.copyOfRange(off, off + chunk)
                        else ByteArray(bytesPerCluster).also { System.arraycopy(bytes, off, it, 0, chunk) }
            reader.write(boot.clusterToOffset(c), block, 0, bytesPerCluster)
            off += chunk
        }
        return clusters.first()
    }

    /** 释放簇链（顺 FAT 链清位图 + 清 FAT 项）。 */
    private fun freeChain(first: Long) {
                if (first < 2) return
        // X4 BUG-1 修复：NoFatChain 文件（桌面 VC 连续分配）须按 dataLength 算簇数，
        // 否则 clusterChain 走 FAT 链首簇即跳出，只释放首簇 → 簇泄漏。chainHint 由 parseDir
        // 填；app 自建文件无 hint 走 else（allocAndWriteChain 永远 FAT 链，noFatChain=false 正确）。
        val hint = chainHint[first]
        val chain = if (hint != null) clusterChain(first, hint.noFatChain, hint.dataLength)
                    else clusterChain(first, noFatChain = false, dataLength = 0)
        for (c in chain) {
            writeFatEntry(c, 0L)
            setClusterBit(c, false)
        }
        chainHint.remove(first)   // 清残留：否则新文件复用此簇号且走 FAT 分支时会被旧 hint 污染
    }

    // ---- upcase / 名字哈希 / 校验和 ----

    private fun upcaseChar(ch: Char): Char {
        val t = upcaseTable
        return if (t != null) t[ch.code] else ch.uppercaseChar()
    }

    /** exFAT NameHash：对大写后的名字逐字节（UTF-16LE）滚动哈希（规范 7.4.1）。 */
    private fun nameHash(name: String): Int {
        var hash = 0
        for (ch in name) {
            val up = upcaseChar(ch)
            val lo = up.code and 0xFF
            val hi = (up.code shr 8) and 0xFF
            hash = (((hash and 1) shl 15) or ((hash and 0xFFFF) ushr 1)) + lo
            hash = hash and 0xFFFF
            hash = (((hash and 1) shl 15) or ((hash and 0xFFFF) ushr 1)) + hi
            hash = hash and 0xFFFF
        }
        return hash and 0xFFFF
    }

    /** 目录项组 SetChecksum（规范 6.3.3）：0x85 项偏移 2/3（校验和自身）计算时按 0 处理。 */
    private fun setChecksum(entries: ByteArray): Int {
        var sum = 0
        for (i in entries.indices) {
            if (i == 2 || i == 3) continue   // 跳过 0x85 项的 SetChecksum 字段本身
            val b = entries[i].toInt() and 0xFF
            sum = (((sum and 1) shl 15) or ((sum and 0xFFFF) ushr 1)) + b
            sum = sum and 0xFFFF
        }
        return sum and 0xFFFF
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

    /** 当前时间打包成 exFAT 32 位时间戳。 */
    private fun packTimestamp(): Long {
        val cal = java.util.Calendar.getInstance()
        val sec = cal.get(java.util.Calendar.SECOND) / 2
        val min = cal.get(java.util.Calendar.MINUTE)
        val hour = cal.get(java.util.Calendar.HOUR_OF_DAY)
        val day = cal.get(java.util.Calendar.DAY_OF_MONTH)
        val month = cal.get(java.util.Calendar.MONTH) + 1
        val year = (cal.get(java.util.Calendar.YEAR) - 1980).coerceIn(0, 127)
        return (sec.toLong()) or (min.toLong() shl 5) or (hour.toLong() shl 11) or
            (day.toLong() shl 16) or (month.toLong() shl 21) or (year.toLong() shl 25)
    }

    /**
     * 造完整目录项组字节（0x85 + 0xC0 + N×0xC1）。名字 UTF-16LE，每 0xC1 项 15 字符。
     * [firstCluster]=0 表示空文件（无数据簇）。返回整组字节（32×项数）。
     */
    private fun buildEntrySet(name: String, isDir: Boolean, firstCluster: Long, dataLength: Long, noFatChain: Boolean = false): ByteArray {
        val nameLen = name.length
        val nameEntries = (nameLen + 14) / 15   // ceil(len/15)
        val secondaryCount = 1 + nameEntries    // 0xC0 + N×0xC1
        val total = 1 + secondaryCount
        val buf = ByteArray(total * ENTRY_SIZE)

        // --- 0x85 文件目录项 ---
        buf[0] = TYPE_FILE.toByte()
        buf[1] = secondaryCount.toByte()
        // 偏移 2/3 SetChecksum 稍后填。
        val attr = if (isDir) ATTR_DIRECTORY else 0x20  // 目录 / 存档
        putU16(buf, 4, attr)
        val ts = packTimestamp()
        putU32(buf, 8, ts)   // Create
        putU32(buf, 12, ts)  // LastModified
        putU32(buf, 16, ts)  // LastAccess

        // --- 0xC0 流扩展项 ---
        val s = ENTRY_SIZE
        buf[s] = TYPE_STREAM_EXT.toByte()
        // flags：bit0 AllocationPossible（有数据），bit1 NoFatChain（连续分配，W3）。
        var sflags = if (firstCluster >= 2) 0x01 else 0x00
        if (noFatChain) sflags = sflags or FLAG_NO_FAT_CHAIN
        buf[s + 1] = sflags.toByte()
        buf[s + 3] = nameLen.toByte()   // NameLength
        putU16(buf, s + 4, nameHash(name))  // NameHash
        putU64(buf, s + 8, dataLength)      // ValidDataLength
        putU32(buf, s + 20, if (firstCluster >= 2) firstCluster else 0L)  // FirstCluster
        putU64(buf, s + 24, dataLength)     // DataLength

        // --- N×0xC1 文件名项 ---
        var ci = 0
        for (e in 0 until nameEntries) {
            val eo = (2 + e) * ENTRY_SIZE
            buf[eo] = TYPE_FILE_NAME.toByte()
            var k = 0
            while (k < 15 && ci < nameLen) {
                putU16(buf, eo + 2 + k * 2, name[ci].code)
                k++; ci++
            }
        }

        // 填 SetChecksum。
        putU16(buf, 2, setChecksum(buf))
        return buf
    }

    // ---- 目录写：定位空闲槽 / 写入 / 删除 ----

    private class DirCtx(val chain: List<Long>, val buf: ByteArray)

    private fun openDir(dirFirstCluster: Long): DirCtx {
        val first = if (dirFirstCluster < 2) boot.rootCluster else dirFirstCluster
        val chain = clusterChain(first, noFatChain = false, dataLength = 0)
        val buf = readChain(chain, -1)
        return DirCtx(chain, buf)
    }

    /** 目录 buf 内第 [idx] 字节 → 卷内逻辑偏移。 */
    private fun dirLogical(ctx: DirCtx, idx: Int): Long {
        val clusterIdx = idx / bytesPerCluster
        val within = idx % bytesPerCluster
        return boot.clusterToOffset(ctx.chain[clusterIdx]) + within
    }

    /** 找连续 [count] 个空闲/结尾槽（32B/槽）。返回起始字节下标；不足返回 -1。 */
    private fun findFreeSlots(buf: ByteArray, count: Int): Int {
        var i = 0
        var runStart = -1
        var runLen = 0
        while (i + ENTRY_SIZE <= buf.size) {
            val type = buf[i].toInt() and 0xFF
            val free = (type == 0x00) || (type and 0x80 == 0)  // EndOfDir 或 InUse=0
            if (free) {
                if (runStart < 0) runStart = i
                runLen++
                if (runLen >= count) return runStart
            } else {
                runStart = -1; runLen = 0
            }
            i += ENTRY_SIZE
        }
        return -1
    }

    /** 定位名为 [name] 的项组：返回 (0x85 项字节下标, 组项数)；未找到 null。 */
    private fun locateEntry(ctx: DirCtx, name: String): Pair<Int, Int>? {
        val buf = ctx.buf
        var i = 0
        while (i + ENTRY_SIZE <= buf.size) {
            val type = buf[i].toInt() and 0xFF
            if (type == 0x00) break
            if (type == TYPE_FILE) {
                val parsed = parseFileEntryGroup(buf, i)
                if (parsed != null && parsed.entry.name == name) return Pair(i, parsed.consumedEntries)
                if (parsed != null) { i += parsed.consumedEntries * ENTRY_SIZE; continue }
            }
            i += ENTRY_SIZE
        }
        return null
    }


    /**
     * 扩展目录簇链（W2）：在 [ctx] 链尾追加一个新簇（alloc -> 挂 FAT -> 清零），返回刷新后的 ctx。
     * 失败（无空闲簇）返回 null。新簇全 0 = EndOfDir 标记，findFreeSlots 视为空闲槽。
     * 子目录扩簇后同步更新其 0xC0 流扩展项（在父目录中）：清 NoFatChain、DataLength/ValidDataLength
     * = 新簇数×簇大小、重算 SetChecksum、同步 chainHint。root 无 0xC0 项（引导扇区描述），跳过。
     */
    private fun expandDir(ctx: DirCtx): DirCtx? {
        val tail = ctx.chain.lastOrNull() ?: return null
        val newC = allocCluster()
        if (newC < 2) return null
        writeFatEntry(tail, newC)        // 旧尾簇 -> 新簇
        writeFatEntry(newC, EOC)         // 新簇为尾，EOC
        // 新簇清零（0x00 = EndOfDir，free slots）。整簇写 0。
        reader.write(boot.clusterToOffset(newC), ByteArray(bytesPerCluster), 0, bytesPerCluster)
        val newChain = clusterChain(ctx.chain.first(), noFatChain = false, dataLength = 0)
        val newBuf = readChain(newChain, -1)
        // 子目录扩簇后须更新其 0xC0 流扩展项（在父目录中），否则 NoFatChain=true 与新 FAT 链矛盾
        // （chkdsk 判错）、DataLength 仍一簇（桌面 VC 只读首簇）、chainHint 漏记新簇（freeChain 簇泄漏）。
        val firstC = ctx.chain.first()
        if (firstC != boot.rootCluster) {
            val newDataLen = newChain.size.toLong() * bytesPerCluster
            chainHint[firstC] = ChainHint(false, newDataLen)   // 同步 chainHint：NoFatChain=false, N 簇
            fixSubDirStreamExt(boot.rootCluster, firstC, newDataLen)
        }
        return DirCtx(newChain, newBuf)
    }

    /**
     * 从 [dirFirstCluster] 起递归查找首簇为 [targetFirstCluster] 的子目录项组，
     * read-modify-write 其 0xC0 流扩展项：清 NoFatChain 位、ValidDataLength/DataLength=[newDataLen]、
     * 重算 SetChecksum 并逐项落盘。找不到时返回 false（chainHint 已在 expandDir 更新，freeChain 不泄漏）。
     */
    private fun fixSubDirStreamExt(dirFirstCluster: Long, targetFirstCluster: Long, newDataLen: Long): Boolean {
        val chain = clusterChain(dirFirstCluster, noFatChain = false, dataLength = 0)
        if (chain.isEmpty()) return false
        val buf = readChain(chain, -1)
        val ctx = DirCtx(chain, buf)
        var i = 0
        while (i + ENTRY_SIZE <= buf.size) {
            val type = buf[i].toInt() and 0xFF
            if (type == 0x00) break
            if (type == TYPE_FILE) {
                val secondaryCount = buf[i + 1].toInt() and 0xFF
                val totalEntries = secondaryCount + 1
                if (i + totalEntries * ENTRY_SIZE <= buf.size) {
                    val s = i + ENTRY_SIZE
                    if ((buf[s].toInt() and 0xFF) == TYPE_STREAM_EXT) {
                        val fc = u32(buf, s + 20)
                        val attr = u16(buf, i + 4)
                        val isDir = (attr and ATTR_DIRECTORY) != 0
                        if (isDir && fc == targetFirstCluster) {
                            // 命中：read-modify-write 0xC0 流扩展项
                            val oldFlags = buf[s + 1].toInt() and 0xFF
                            buf[s + 1] = (oldFlags and FLAG_NO_FAT_CHAIN.inv()).toByte()  // 清 NoFatChain
                            putU64(buf, s + 8, newDataLen)    // ValidDataLength
                            putU64(buf, s + 24, newDataLen)   // DataLength
                            val entryBytes = buf.copyOfRange(i, i + totalEntries * ENTRY_SIZE)
                            putU16(entryBytes, 2, setChecksum(entryBytes))  // 重算 SetChecksum
                            for (e in 0 until totalEntries) {  // 逐项落盘（可能跨簇边界）
                                reader.write(dirLogical(ctx, i + e * ENTRY_SIZE), entryBytes, e * ENTRY_SIZE, ENTRY_SIZE)
                            }
                            return true
                        }
                        if (isDir && fc >= 2 && fc != targetFirstCluster && fc != dirFirstCluster) {
                            if (fixSubDirStreamExt(fc, targetFirstCluster, newDataLen)) return true
                        }
                    }
                }
                i += totalEntries * ENTRY_SIZE
                continue
            }
            i += ENTRY_SIZE
        }
        return false
    }

    override fun writeFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        if (name.isEmpty() || bitmapChain.isEmpty()) return false
        val ctx = openDir(dirFirstCluster)
        if (locateEntry(ctx, name) != null) return false   // 已存在
        // 先分配数据簇（满盘抛 VolumeFullException），再写目录项。
        val (firstCluster, noFat) = allocDataClusters(bytes)
        return writeDirEntry(dirFirstCluster, name, firstCluster, bytes.size.toLong(), noFat)
    }

    /**
     * 分配数据簇并写入内容。空文件返回 (0, false)。满盘抛 VolumeFullException
     * （不残留：连续段满盘直接回退 FAT 链；allocAndWriteChain 分配失败内部回滚已占位簇）。
     * 两条分支都显式登记 chainHint，杜绝旧 hint 残留污染 freeChain 的簇数推导。
     */
    private fun allocDataClusters(bytes: ByteArray): Pair<Long, Boolean> {
        if (bytes.isEmpty()) return 0L to false
        val need = (bytes.size + bytesPerCluster - 1) / bytesPerCluster
        val contStart = allocContiguous(need)
        if (contStart >= 2) {
            // W3：NoFatChain 连续分配——写数据到连续簇段，不写 FAT 链。
            var off = 0
            for (k in 0 until need) {
                val chunk = minOf(bytesPerCluster, bytes.size - off)
                val block = if (chunk == bytesPerCluster) bytes.copyOfRange(off, off + chunk)
                            else ByteArray(bytesPerCluster).also { System.arraycopy(bytes, off, it, 0, chunk) }
                reader.write(boot.clusterToOffset(contStart + k), block, 0, bytesPerCluster)
                off += chunk
            }
            chainHint[contStart] = ChainHint(true, bytes.size.toLong())
            return contStart to true
        }
        // 回退 FAT 链（空间碎片化无连续段；真正空间不足由 allocAndWriteChain 抛 VolumeFullException）。
        val first = allocAndWriteChain(bytes)
        chainHint[first] = ChainHint(false, bytes.size.toLong())
        return first to false
    }

    /**
     * 把已分配好数据簇的文件写入目录项（目录满则扩簇重试）。
     * 无空间放目录项时回滚数据簇并返回 false。
     */
    private fun writeDirEntry(dirFirstCluster: Long, name: String, firstCluster: Long, dataLength: Long, noFat: Boolean): Boolean {
        var ctx = openDir(dirFirstCluster)
        val entrySet = buildEntrySet(name, isDir = false, firstCluster = firstCluster, dataLength = dataLength, noFatChain = noFat)
        val slots = entrySet.size / ENTRY_SIZE
        var pos = findFreeSlots(ctx.buf, slots)
        // W2：目录满则扩簇（链尾追加新簇 -> 挂 FAT -> 清零 -> 刷新 ctx）后重试，直至放下或无空间。
        while (pos < 0) {
            ctx = expandDir(ctx) ?: run {
                if (firstCluster >= 2) freeChain(firstCluster)   // 回滚数据簇
                return false
            }
            pos = findFreeSlots(ctx.buf, slots)
        }
        // 逐项写入（可能跨簇边界，故按项算逻辑偏移）。
        for (e in 0 until slots) {
            reader.write(dirLogical(ctx, pos + e * ENTRY_SIZE), entrySet, e * ENTRY_SIZE, ENTRY_SIZE)
        }
        return true
    }

    override fun deleteFile(dirFirstCluster: Long, name: String): Boolean {
        if (bitmapChain.isEmpty()) return false
        val ctx = openDir(dirFirstCluster)
        val (base, count) = locateEntry(ctx, name) ?: return false
        // 取首簇释放数据。
        val parsed = parseFileEntryGroup(ctx.buf, base)
        val firstCluster = parsed?.entry?.firstCluster ?: 0L
        // 清 InUse 位（type & 0x7F），逐项写回。
        for (e in 0 until count) {
            val off = dirLogical(ctx, base + e * ENTRY_SIZE)
            val t = (reader.read(off, 1)[0].toInt() and 0xFF) and 0x7F
            reader.write(off, byteArrayOf(t.toByte()), 0, 1)
        }
        if (firstCluster >= 2) freeChain(firstCluster)
        return true
    }

    override fun overwriteFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        // W19 优化：大小不变时走原地覆盖（不重新分配簇链），与 FAT 层语义对齐。
        //   大小变化则回退到删旧+写新（非崩溃原子，与 FAT 同级）。
        val dir = if (dirFirstCluster < 2) boot.rootCluster else dirFirstCluster
        val entry = parseDir(dir).firstOrNull { it.name == name && !it.isDirectory } ?: return false
        if (entry.size == bytes.size.toLong() && entry.firstCluster >= 2 && bytes.isNotEmpty()) {
            // 大小不变：原地逐簇覆盖数据，不重新分配。noFatChain 判定沿用 chainHint（X4 同模式）。
            val hint = chainHint[entry.firstCluster]
            val noFat = hint?.noFatChain ?: false
            val chain = clusterChain(entry.firstCluster, noFat, entry.size)
            var off = 0
            for (c in chain) {
                val chunk = minOf(bytesPerCluster, bytes.size - off)
                if (chunk <= 0) break
                // 与 writeFile 一致：整簇对齐写，尾簇补零，避免越界读源数组。
                val block = if (chunk == bytesPerCluster) bytes.copyOfRange(off, off + chunk)
                            else ByteArray(bytesPerCluster).also { System.arraycopy(bytes, off, it, 0, chunk) }
                reader.write(boot.clusterToOffset(c), block, 0, bytesPerCluster)
                off += chunk
            }
            return true
        }
        // 大小变化：先建后拆（对齐 FAT 层 FatFileSystem.overwriteFile）。
        //   ① 先分配新数据簇（满盘抛 VolumeFullException，此时旧文件完好无损，绝不先删）；
        //   ② 分配成功再删旧（释放旧簇 + 清旧目录项）；③ 写新目录项复用释放出的 slot。
        // 旧实现"先 deleteFile 后 writeFile"在满盘时会丢掉整个原文件（H1），已废弃。
        val (newFirst, noFat) = allocDataClusters(bytes)
        if (!deleteFile(dirFirstCluster, name)) {
            if (newFirst >= 2) freeChain(newFirst)   // 删旧失败则回滚刚分配的新簇
            return false
        }
        return writeDirEntry(dirFirstCluster, name, newFirst, bytes.size.toLong(), noFat)
    }

    // ==== W7/W9/W10/W14 exFAT 目录操作（纯新增，不动上方 writeFile/overwriteFile/deleteFile）====

    /** 旧项元数据：从 0x85 attr + 0xC0 流扩展直接取字节。FsEntry 不暴露 noFatChain，且目录 size 恒 0。 */
    private class DirItemMeta(val isDir: Boolean, val firstCluster: Long, val dataLength: Long, val noFatChain: Boolean)

    private fun readItemMeta(buf: ByteArray, base: Int): DirItemMeta {
        val attr = u16(buf, base + 4)
        val s = base + ENTRY_SIZE
        val flags = buf[s + 1].toInt() and 0xFF
        return DirItemMeta(
            isDir = (attr and ATTR_DIRECTORY) != 0,
            firstCluster = u32(buf, s + 20),
            dataLength = u64(buf, s + 24),
            noFatChain = (flags and FLAG_NO_FAT_CHAIN) != 0,
        )
    }

    /** 把已建好的 entry set 写入目录空位（满则 expandDir 重试）。无空间返回 false。落盘循环同 writeDirEntry。 */
    private fun writeEntrySet(dirFirstCluster: Long, entrySet: ByteArray): Boolean {
        var ctx = openDir(dirFirstCluster)
        val slots = entrySet.size / ENTRY_SIZE
        var pos = findFreeSlots(ctx.buf, slots)
        while (pos < 0) {
            ctx = expandDir(ctx) ?: return false
            pos = findFreeSlots(ctx.buf, slots)
        }
        for (e in 0 until slots) {
            reader.write(dirLogical(ctx, pos + e * ENTRY_SIZE), entrySet, e * ENTRY_SIZE, ENTRY_SIZE)
        }
        return true
    }

    /** 清 entry set 的 InUse 位（type & 0x7F，逐项写回），不动数据簇。同 deleteFile 删项逻辑。 */
    private fun clearEntrySet(ctx: DirCtx, base: Int, count: Int) {
        for (e in 0 until count) {
            val off = dirLogical(ctx, base + e * ENTRY_SIZE)
            val t = (reader.read(off, 1)[0].toInt() and 0xFF) and 0x7F
            reader.write(off, byteArrayOf(t.toByte()), 0, 1)
        }
    }

    /**
     * W7 重命名：exFAT 改名 = 重建整组 entry set（名字长度变化会改 NameLength/SecondaryCount/
     * NameHash/SetChecksum，无法原地改）。先建 newName 组（复用旧首簇/DataLength/isDir/noFatChain）
     * 写入目录空位，成功后再清旧组 InUse 位。先建后拆：中途失败旧项完好。数据簇与 chainHint 全不动。
     */
    override fun rename(dirFirstCluster: Long, oldName: String, newName: String): Boolean {
        if (bitmapChain.isEmpty()) return false
        if (newName.isEmpty() || newName.length > 255 || oldName == newName) return false
        val ctx = openDir(dirFirstCluster)
        if (locateEntry(ctx, newName) != null) return false      // 新名已存在
        val (base, count) = locateEntry(ctx, oldName) ?: return false
        val m = readItemMeta(ctx.buf, base)
        val entrySet = buildEntrySet(newName, m.isDir, m.firstCluster, m.dataLength, m.noFatChain)
        if (!writeEntrySet(dirFirstCluster, entrySet)) return false   // 目录满且扩不了：旧项未动
        // 重新 openDir 取旧项最新逻辑位（写新组可能已 expandDir，旧簇不变故 base 仍有效，但保险重定位）。
        val ctx2 = openDir(dirFirstCluster)
        val loc = locateEntry(ctx2, oldName) ?: return true      // 理论必存在；防御
        clearEntrySet(ctx2, loc.first, loc.second)
        return true
    }

    /**
     * W9 新建目录：分配一簇作目录数据 → 整簇清零（0x00 = EndOfDir）→ 写 FAT 项 EOC
     * （关键：openDir/parseDir 硬编码走 FAT 链读目录，故新簇必须挂 FAT，否则将来读到旧垃圾值）
     * → 父目录写 entry set（isDir=true，DataLength=一簇大小，NoFatChain 单簇连续）
     * → 登记 chainHint 防将来 freeChain 簇泄漏。写项失败回滚：清 FAT + 释放簇。
     * 返回新目录首簇；失败返回 0（接口语义，非任务卡的 -1）。
     */
    override fun mkdir(dirFirstCluster: Long, name: String): Long {
        if (name.isEmpty() || name.length > 255 || bitmapChain.isEmpty()) return 0L
        val ctx = openDir(dirFirstCluster)
        if (locateEntry(ctx, name) != null) return 0L            // 同名已存在
        val newC = allocCluster()                                // 内部已置位图
        if (newC < 2) return 0L
        reader.write(boot.clusterToOffset(newC), ByteArray(bytesPerCluster), 0, bytesPerCluster)  // 整簇清零
        writeFatEntry(newC, EOC)                                 // 单簇挂 FAT 尾，openDir 可读
        val dataLen = bytesPerCluster.toLong()
        val entrySet = buildEntrySet(name, isDir = true, firstCluster = newC, dataLength = dataLen, noFatChain = true)
        if (!writeEntrySet(dirFirstCluster, entrySet)) {         // 父目录满且扩不了：回滚
            writeFatEntry(newC, 0L)
            setClusterBit(newC, false)
            return 0L
        }
        chainHint[newC] = ChainHint(true, dataLen)               // 防将来 freeChain 只释放首簇
        return newC
    }

    /**
     * W10 同卷移动：数据簇不搬，纯目录项搬家。exFAT 目录不记父（无 ..），比 FAT 简单。
     * 读源组全字段 → dstDir 建同名组（复用首簇/DataLength/isDir/noFatChain）→ 删 srcDir 源组。先建后拆。
     * 同目录（含 <2 归一到 rootCluster）视为无操作直接 true：避免两份独立 ctx 快照互相覆盖。
     */
    override fun move(srcDirFirstCluster: Long, name: String, dstDirFirstCluster: Long): Boolean {
        if (bitmapChain.isEmpty()) return false
        val src = if (srcDirFirstCluster < 2) boot.rootCluster else srcDirFirstCluster
        val dst = if (dstDirFirstCluster < 2) boot.rootCluster else dstDirFirstCluster
        if (src == dst) return true                              // 同目录无操作
        val srcCtx = openDir(src)
        val (base, _) = locateEntry(srcCtx, name) ?: return false
        val m = readItemMeta(srcCtx.buf, base)
        val dstCtx = openDir(dst)
        if (locateEntry(dstCtx, name) != null) return false      // 目标已存在同名
        val entrySet = buildEntrySet(name, m.isDir, m.firstCluster, m.dataLength, m.noFatChain)
        if (!writeEntrySet(dst, entrySet)) return false          // 目标满且扩不了：源未动
        val srcCtx2 = openDir(src)                               // 重定位源（dst 若是 src 已排除）
        val loc = locateEntry(srcCtx2, name) ?: return true
        clearEntrySet(srcCtx2, loc.first, loc.second)
        return true
    }

    /** 目录是否空：扫其簇内容，遇 0x00=EndOfDir 判空；遇 0x85（InUse 文件项）判非空；已删项(InUse=0)跳过。 */
    private fun isDirEmpty(firstCluster: Long, dataLength: Long, noFatChain: Boolean): Boolean {
        val chain = clusterChain(firstCluster, noFatChain, dataLength)
        if (chain.isEmpty()) return true
        val buf = readChain(chain, -1)
        var i = 0
        while (i + ENTRY_SIZE <= buf.size) {
            val type = buf[i].toInt() and 0xFF
            if (type == 0x00) return true                        // EndOfDir，其后全空
            if (type == TYPE_FILE) return false                  // 存活文件/子目录项
            i += ENTRY_SIZE                                      // 0xC0/0xC1 从属项 或 已删项，跳过
        }
        return true
    }

    /**
     * W14 删目录：非目录返 false。判空后 freeChain（目录首簇）+ 清父目录该项 InUse。
     * 关键：freeChain 靠 chainHint 判 NoFatChain 算簇数，外部 VC 建的目录无 hint 会漏释放 →
     * 删前显式登记 chainHint。
     *
     * [recursive]=false：非空目录拒绝（返 false）。true：先递归清空子项（子目录 rmdir、
     *   文件 deleteFile，以本目录首簇为父句柄），再删本目录——与 FAT/NTFS 同款先清后删语义。
     *   任一子项删失败即中止、不硬删父目录（不留孤儿簇）。
     */
    override fun rmdir(dirFirstCluster: Long, name: String, recursive: Boolean): Boolean {
        if (bitmapChain.isEmpty()) return false
        val ctx = openDir(dirFirstCluster)
        val (base, count) = locateEntry(ctx, name) ?: return false
        val m = readItemMeta(ctx.buf, base)
        if (!m.isDir) return false                               // 不是目录
        if (m.firstCluster >= 2 && !isDirEmpty(m.firstCluster, m.dataLength, m.noFatChain)) {
            if (!recursive) return false                         // 非空且非递归：拒绝
            for (child in listDir(m.firstCluster)) {
                val ok = if (child.isDirectory) rmdir(m.firstCluster, child.name, recursive = true)
                         else deleteFile(m.firstCluster, child.name)
                if (!ok) return false                            // 子项删失败即中止，不硬删父
            }
        }
        if (m.firstCluster >= 2) {
            chainHint[m.firstCluster] = ChainHint(m.noFatChain, m.dataLength)  // 防漏释放
            freeChain(m.firstCluster)
        }
        // 递归清空后 ctx 快照已过期（子项 clearEntrySet 改了本目录簇），但清的是父目录里
        //   本条目 base/count（本条目组不随子项增删移动，base 仍有效），无需重定位。
        clearEntrySet(ctx, base, count)
        return true
    }

    override fun invalidateFsInfo() { /* exFAT 无 FAT32 FSInfo，空操作 */ }

    // ---- 小工具 ----
    private fun u16(b: ByteArray, o: Int) =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    private fun u32(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF).toLong()) or
        ((b[o + 1].toInt() and 0xFF).toLong() shl 8) or
        ((b[o + 2].toInt() and 0xFF).toLong() shl 16) or
        ((b[o + 3].toInt() and 0xFF).toLong() shl 24)

    private fun u64(b: ByteArray, o: Int): Long {
        var v = 0L
        for (k in 0 until 8) v = v or ((b[o + k].toInt() and 0xFF).toLong() shl (8 * k))
        return v
    }

    companion object {
        const val ENTRY_SIZE = 32

        // EntryType 字节：bit7=InUse。带 InUse 的常见类型：
        const val TYPE_ALLOCATION_BITMAP = 0x81
        const val TYPE_UPCASE_TABLE = 0x82
        const val TYPE_VOLUME_LABEL = 0x83
        const val TYPE_FILE = 0x85
        const val TYPE_STREAM_EXT = 0xC0
        const val TYPE_FILE_NAME = 0xC1

        // 文件属性（0x85 项偏移 4，u16）。
        const val ATTR_DIRECTORY = 0x10

        // 流扩展 flags（0xC0 项偏移 1）：bit1 = NoFatChain（连续分配）。
        const val FLAG_NO_FAT_CHAIN = 0x02

        const val EOC = 0xFFFFFFFFL
        const val BAD_CLUSTER = 0xFFFFFFF7L

        /**
         * 从 [reader] 解析 exFAT 引导扇区并建文件系统。非 exFAT 抛 [IllegalArgumentException]。
         * 建成后立即扫根目录回填卷标。
         */
        fun mount(reader: VolumeReader): ExFatFileSystem {
            val boot = ExFatBoot.parse(reader.read(0, 512))
            val fs = ExFatFileSystem(reader, boot)
            fs.scanRootMeta()   // 回填卷标 + 分配位图 + upcase 表（写方向必需）
            return fs
        }
    }
}
