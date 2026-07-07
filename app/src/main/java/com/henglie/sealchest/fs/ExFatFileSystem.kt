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

        val hint = chainHint[firstCluster]
        val noFatChain = hint?.noFatChain ?: false
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
    private fun allocAndWriteChain(bytes: ByteArray): Long {
        if (bytes.isEmpty()) return 0L
        val need = ((bytes.size + bytesPerCluster - 1) / bytesPerCluster)
        val clusters = ArrayList<Long>(need)
        for (k in 0 until need) {
            val c = allocCluster()
            if (c < 2) { clusters.forEach { setClusterBit(it, false) }; return 0L }  // 回滚
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
        val chain = clusterChain(first, noFatChain = false, dataLength = 0)
        for (c in chain) {
            writeFatEntry(c, 0L)
            setClusterBit(c, false)
        }
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
    private fun buildEntrySet(name: String, isDir: Boolean, firstCluster: Long, dataLength: Long): ByteArray {
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
        // flags：不设 NoFatChain（走 FAT 链）。有数据时 bit0 AllocationPossible=1。
        buf[s + 1] = if (firstCluster >= 2) 0x01 else 0x00
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

    override fun writeFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        if (name.isEmpty() || bitmapChain.isEmpty()) return false
        val ctx = openDir(dirFirstCluster)
        if (locateEntry(ctx, name) != null) return false   // 已存在
        val firstCluster = if (bytes.isEmpty()) 0L else allocAndWriteChain(bytes)
        if (bytes.isNotEmpty() && firstCluster < 2) return false  // 分配失败
        val entrySet = buildEntrySet(name, isDir = false, firstCluster = firstCluster, dataLength = bytes.size.toLong())
        val slots = entrySet.size / ENTRY_SIZE
        val pos = findFreeSlots(ctx.buf, slots)
        if (pos < 0) {
            if (firstCluster >= 2) freeChain(firstCluster)   // 回滚数据簇
            return false   // 目录满（本版不扩目录簇）
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
        // 覆写 = 删除旧项（释放旧簇）+ 写新项。非崩溃原子，与 FAT 层同级别。
        if (!deleteFile(dirFirstCluster, name)) return false
        return writeFile(dirFirstCluster, name, bytes)
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
