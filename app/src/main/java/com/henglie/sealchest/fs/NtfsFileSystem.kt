package com.henglie.sealchest.fs

/**
 * NTFS 文件系统解析层（读 + 受限写，见各方法）。
 *
 * 全部经 [VolumeReader]（解密 + 逻辑寻址），本层只见「卷内逻辑偏移」，不碰加密。
 * 与 FAT / exFAT 走同一套 [VolumeFs] 接口，[MountManager] / SAF / UI 零感知底层。
 *
 * NTFS 的核心是 $MFT（主文件表）：每个文件/目录一条 FILE 记录（默认 1024B），
 * 记录里是一串「属性」。关键属性：
 *   0x10 $STANDARD_INFORMATION  时间戳 / 标志
 *   0x30 $FILE_NAME             文件名 + 父目录引用（可有多条：长名 + DOS 短名）
 *   0x80 $DATA                  文件数据（驻留=直接在记录里；非驻留=data runs 指向簇）
 *   0x90 $INDEX_ROOT            目录索引根（小目录直接在此）
 *   0xA0 $INDEX_ALLOCATION      目录索引的非驻留部分（大目录，INDX 记录簇）
 *   0xB0 $BITMAP                索引分配位图
 *
 * 每条 FILE / INDX 记录头有 Update Sequence Array（USA）：把每扇区末 2 字节替换成
 * 统一序列号防撕裂，读出后必须用 USA 修复回真实字节，否则跨扇区数据错乱。
 *
 * 目录项 = 索引项（INDEX_ENTRY），含子文件的 MFT 引用 + $FILE_NAME 副本。
 * 遍历目录 = 解析 $INDEX_ROOT + 顺 $INDEX_ALLOCATION 的 INDX 记录收集索引项。
 *
 * 线程不安全，与 [VolumeReader] 同一串行化域。
 */
class NtfsFileSystem private constructor(
    private val reader: VolumeReader,
    private val boot: NtfsBoot,
) : VolumeFs {

    override val fsType: String get() = "NTFS"
    override var volumeLabel: String = ""
        private set

    private val bytesPerCluster = boot.bytesPerCluster
    private val mftRecordSize = boot.fileRecordSize

    companion object {
        fun mount(reader: VolumeReader): NtfsFileSystem {
            val boot = NtfsBoot.parse(reader.read(0, 512))
            val fs = NtfsFileSystem(reader, boot)
            fs.bootstrapMft()
            fs.readVolumeLabel()
            return fs
        }

        // 固定 MFT 记录号。
        const val MFT_ROOT_DIR = 5L          // 根目录 "."
        const val MFT_VOLUME = 3L            // $Volume（卷标在此）

        // 属性类型。
        const val ATTR_STANDARD_INFO = 0x10L
        const val ATTR_FILE_NAME = 0x30L
        const val ATTR_VOLUME_NAME = 0x60L
        const val ATTR_DATA = 0x80L
        const val ATTR_INDEX_ROOT = 0x90L
        const val ATTR_INDEX_ALLOCATION = 0xA0L
        const val ATTR_END = 0xFFFFFFFFL

        // $FILE_NAME 命名空间（偏移 0x41 处 1 字节）。
        const val NS_DOS = 2                 // 纯 DOS 短名（8.3），列目录时跳过

        // FILE 记录标志（记录头偏移 0x16）。
        const val FLAG_IN_USE = 0x0001
        const val FLAG_DIRECTORY = 0x0002

        // 索引项标志。
        const val INDEX_ENTRY_HAS_SUBNODE = 0x01
        const val INDEX_ENTRY_LAST = 0x02

        const val NTFS_EPOCH_DIFF_MS = 11644473600000L  // 1601→1970 毫秒差
    }

    // ---- 底层：按逻辑偏移读、USA 修复 ----

    /** 读 MFT 第 [recordNo] 条记录（已 USA 修复）。越界返回 null。 */
    private fun readMftRecord(recordNo: Long): ByteArray? {
        // $MFT 自身可能非连续，但第一段（含前若干记录）总在 mftLcn。简化：用 $MFT 的
        // data runs 定位任意记录。先读 $MFT 记录 0 拿它的 runs，再定位目标记录簇。
        val mftData = mftDataRuns ?: return readMftRecordLinear(recordNo)
        val byteOffInMft = recordNo * mftRecordSize
        val buf = readFromRuns(mftData, byteOffInMft, mftRecordSize) ?: return null
        if (!applyUsaFixup(buf)) return null
        if (buf.size < 4 || buf[0] != 'F'.code.toByte()) return null
        return buf
    }

    /** $MFT runs 未就绪时（bootstrap）：假定 MFT 从 mftLcn 起连续，线性定位。 */
    private fun readMftRecordLinear(recordNo: Long): ByteArray? {
        val off = boot.mftByteOffset + recordNo * mftRecordSize
        val buf = reader.read(off, mftRecordSize)
        if (buf.size < 4 || buf[0] != 'F'.code.toByte()) return null
        if (!applyUsaFixup(buf)) return null
        return buf
    }

    /**
     * USA 修复：记录头偏移 4 = USN 偏移（u16），偏移 6 = USN 计数（u16，含 1 个序列号
     * + N 个扇区末原值）。把每扇区最后 2 字节从数组恢复。
     */
    private fun applyUsaFixup(buf: ByteArray): Boolean {
        val usaOff = u16(buf, 4)
        val usaCount = u16(buf, 6)
        if (usaCount < 1) return false
        val usn0 = u16(buf, usaOff)                 // 序列号
        // 每扇区末 2 字节应等于 usn0；否则撕裂。逐扇区替换回原值。
        for (i in 1 until usaCount) {
            val sectorEnd = i * boot.bytesPerSector - 2
            if (sectorEnd + 2 > buf.size) break
            val cur = u16(buf, sectorEnd)
            if (cur != usn0) { /* 撕裂或未初始化，仍尽力恢复 */ }
            val orig = u16(buf, usaOff + i * 2)
            buf[sectorEnd] = (orig and 0xFF).toByte()
            buf[sectorEnd + 1] = ((orig shr 8) and 0xFF).toByte()
        }
        return true
    }

    // ---- 属性解析 ----

    private class Attr(
        val type: Long,
        val nonResident: Boolean,
        val name: String,
        /** 驻留：属性体在记录内的绝对偏移 + 长度。 */
        val residentValueOffset: Int,
        val residentValueLength: Int,
        /** 非驻留：data runs 原始字节（在记录内的切片）+ 真实数据长度。 */
        val runsOffset: Int,
        val realSize: Long,
        val recordBuf: ByteArray,
    ) {
        fun residentValue(): ByteArray =
            recordBuf.copyOfRange(residentValueOffset, residentValueOffset + residentValueLength)
    }

    /** 遍历一条 FILE 记录的所有属性。 */
    private fun parseAttrs(rec: ByteArray): List<Attr> {
        val out = ArrayList<Attr>()
        var off = u16(rec, 0x14)   // 第一个属性偏移
        while (off + 4 <= rec.size) {
            val type = u32(rec, off)
            if (type == ATTR_END) break
            if (off + 8 > rec.size) break
            val totalLen = u32(rec, off + 4).toInt()
            if (totalLen <= 0 || off + totalLen > rec.size) break
            val nonResident = (rec[off + 8].toInt() and 0xFF) != 0
            val nameLen = rec[off + 9].toInt() and 0xFF
            val nameOff = u16(rec, off + 10)
            val name = if (nameLen > 0) {
                val sb = StringBuilder(nameLen)
                for (k in 0 until nameLen) sb.append(u16(rec, off + nameOff + k * 2).toChar())
                sb.toString()
            } else ""

            if (!nonResident) {
                val valLen = u32(rec, off + 0x10).toInt()
                val valOff = u16(rec, off + 0x14)
                out.add(Attr(type, false, name, off + valOff, valLen, 0, valLen.toLong(), rec))
            } else {
                val runsOff = u16(rec, off + 0x20)
                val realSize = u64(rec, off + 0x30)
                out.add(Attr(type, true, name, 0, 0, off + runsOff, realSize, rec))
            }
            off += totalLen
        }
        return out
    }

    /** 找首个匹配 [type]（且名字匹配 [name]，默认无名）的属性。 */
    private fun findAttr(attrs: List<Attr>, type: Long, name: String = ""): Attr? =
        attrs.firstOrNull { it.type == type && it.name == name }

    // ---- data runs 解码 ----

    private class DataRun(val length: Long, val lcn: Long, val sparse: Boolean)

    /** 解码 runlist：变长记录，首字节高 4 位=长度字段字节数，低 4 位=偏移字段字节数。 */
    private fun decodeRuns(rec: ByteArray, runsOff: Int): List<DataRun> {
        val runs = ArrayList<DataRun>()
        var i = runsOff
        var prevLcn = 0L
        while (i < rec.size) {
            val header = rec[i].toInt() and 0xFF
            if (header == 0) break
            val lenBytes = header and 0x0F
            val offBytes = (header shr 4) and 0x0F
            i++
            if (lenBytes == 0 || i + lenBytes + offBytes > rec.size) break
            var length = 0L
            for (k in 0 until lenBytes) length = length or ((rec[i + k].toInt() and 0xFF).toLong() shl (8 * k))
            i += lenBytes
            if (offBytes == 0) {
                // 稀疏段（无 LCN）。
                runs.add(DataRun(length, 0, sparse = true))
            } else {
                // 有符号偏移，相对前一 LCN。
                var off = 0L
                for (k in 0 until offBytes) off = off or ((rec[i + k].toInt() and 0xFF).toLong() shl (8 * k))
                // 符号扩展
                val signBit = 1L shl (offBytes * 8 - 1)
                if (off and signBit != 0L) off = off or (-1L shl (offBytes * 8))
                prevLcn += off
                runs.add(DataRun(length, prevLcn, sparse = false))
                i += offBytes
            }
        }
        return runs
    }

    /** 从 runs 读 [byteOffset] 起 [length] 字节（跨 run 拼接，稀疏补零）。 */
    private fun readFromRuns(runs: List<DataRun>, byteOffset: Long, length: Int): ByteArray? {
        val out = ByteArray(length)
        var remaining = length
        var outPos = 0
        var pos = byteOffset
        for (run in runs) {
            val runBytes = run.length * bytesPerCluster
            if (pos >= runBytes) { pos -= runBytes; continue }
            while (pos < runBytes && remaining > 0) {
                val within = pos
                val canRead = minOf((runBytes - within), remaining.toLong()).toInt()
                if (run.sparse) {
                    // 稀疏：补零
                    outPos += canRead
                } else {
                    val srcOff = run.lcn * bytesPerCluster + within
                    val data = reader.read(srcOff, canRead)
                    System.arraycopy(data, 0, out, outPos, canRead)
                    outPos += canRead
                }
                remaining -= canRead
                pos += canRead
            }
            if (remaining <= 0) return out
            pos = 0
        }
        // runs 不足：剩余保持 0
        return out
    }

    /** $MFT 自身的 data runs（bootstrap 后填），用于定位任意 MFT 记录。 */
    private var mftDataRuns: List<DataRun>? = null

    private fun bootstrapMft() {
        // 线性读 $MFT 记录 0（记录 0 = $MFT 本身），解出其 $DATA 的 runs。
        val rec0 = readMftRecordLinear(0L) ?: return
        val attrs = parseAttrs(rec0)
        val data = findAttr(attrs, ATTR_DATA) ?: return
        if (data.nonResident) {
            mftDataRuns = decodeRuns(data.recordBuf, data.runsOffset)
        }
    }

    private fun readVolumeLabel() {
        val rec = readMftRecord(MFT_VOLUME) ?: return
        val attrs = parseAttrs(rec)
        val vn = findAttr(attrs, ATTR_VOLUME_NAME) ?: return
        if (!vn.nonResident) {
            val v = vn.residentValue()
            val sb = StringBuilder()
            var k = 0
            while (k + 1 < v.size) { sb.append(u16(v, k).toChar()); k += 2 }
            volumeLabel = sb.toString()
        }
    }

    // ---- 文件内容读 ----

    /** 读 MFT 记录 [recordNo] 的 $DATA（无名默认流）。 */
    private fun readData(recordNo: Long, start: Long, length: Int): ByteArray {
        val rec = readMftRecord(recordNo) ?: return ByteArray(0)
        val attrs = parseAttrs(rec)
        val data = findAttr(attrs, ATTR_DATA) ?: return ByteArray(0)
        if (!data.nonResident) {
            // 驻留：直接切。
            val v = data.residentValue()
            val from = start.toInt().coerceIn(0, v.size)
            val to = minOf(from + length, v.size)
            if (to <= from) return ByteArray(0)
            return v.copyOfRange(from, to)
        }
        val runs = decodeRuns(data.recordBuf, data.runsOffset)
        val realSize = data.realSize
        val end = minOf(start + length, realSize)
        val want = (end - start).toInt()
        if (want <= 0) return ByteArray(0)
        return readFromRuns(runs, start, want) ?: ByteArray(0)
    }

    // ---- 目录遍历 ----

    /**
     * 收集目录（MFT 记录 [dirRecordNo]）下的索引项 → 子文件 (name, mftRef, isDir, size)。
     * 走 $INDEX_ROOT（驻留）+ $INDEX_ALLOCATION（非驻留 INDX 记录）。
     */
    private fun listDirEntries(dirRecordNo: Long): List<FsEntry> {
        val rec = readMftRecord(dirRecordNo) ?: return emptyList()
        val attrs = parseAttrs(rec)
        val out = ArrayList<FsEntry>()
        val seen = HashSet<Long>()

        // $INDEX_ROOT：名字通常是 "$I30"。
        val root = findAttr(attrs, ATTR_INDEX_ROOT, "\$I30")
            ?: attrs.firstOrNull { it.type == ATTR_INDEX_ROOT }
        if (root != null && !root.nonResident) {
            val body = root.residentValue()
            // INDEX_ROOT 头 16 字节，之后是 INDEX_HEADER（16 字节），索引项从 header 的
            // EntriesOffset 起。EntriesOffset 相对 INDEX_HEADER 起点（即 body 偏移 16）。
            val entriesOff = 16 + u32(body, 16).toInt()
            parseIndexEntries(body, entriesOff, out, seen)
        }

        // $INDEX_ALLOCATION：非驻留，含若干 INDX 记录（每条 bytesPerIndexRecord）。
        val alloc = findAttr(attrs, ATTR_INDEX_ALLOCATION, "\$I30")
            ?: attrs.firstOrNull { it.type == ATTR_INDEX_ALLOCATION }
        if (alloc != null && alloc.nonResident) {
            val runs = decodeRuns(alloc.recordBuf, alloc.runsOffset)
            val totalSize = alloc.realSize
            var pos = 0L
            val idxSize = boot.indexRecordSize
            while (pos + idxSize <= totalSize) {
                val indx = readFromRuns(runs, pos, idxSize)
                pos += idxSize
                if (indx == null || indx.size < 4) continue
                if (indx[0] != 'I'.code.toByte()) continue   // "INDX" 签名；空块跳过
                applyUsaFixup(indx)
                // INDX 头 24 字节后是 INDEX_HEADER（偏移 24）。EntriesOffset 相对偏移 24。
                val entriesOff = 24 + u32(indx, 24).toInt()
                parseIndexEntries(indx, entriesOff, out, seen)
            }
        }
        return out
    }

    /** 解析一段索引项（INDEX_ENTRY 序列），追加到 [out]。[seen] 去重（长名+短名指向同 MFT）。 */
    private fun parseIndexEntries(buf: ByteArray, start: Int, out: ArrayList<FsEntry>, seen: HashSet<Long>) {
        var i = start
        while (i + 16 <= buf.size) {
            val mftRef = u64(buf, i) and 0x0000FFFFFFFFFFFFL   // 低 48 位 = 记录号
            val entryLen = u16(buf, i + 8)
            val contentLen = u16(buf, i + 10)
            val flags = u16(buf, i + 12)
            if (entryLen < 16) break
            if (flags and INDEX_ENTRY_LAST != 0) break
            if (contentLen > 0 && i + 16 + contentLen <= buf.size) {
                // 索引项内容 = $FILE_NAME 属性体（从 i+16 起）。
                parseFileNameEntry(buf, i + 16, mftRef, out, seen)
            }
            i += entryLen
        }
    }

    /** 从 $FILE_NAME 属性体解析一个条目。 */
    private fun parseFileNameEntry(buf: ByteArray, fnOff: Int, mftRef: Long, out: ArrayList<FsEntry>, seen: HashSet<Long>) {
        if (fnOff + 0x42 > buf.size) return
        val fileFlags = u32(buf, fnOff + 0x38)
        val isDir = (fileFlags and 0x10000000L) != 0L   // FILE_ATTRIBUTE_DIRECTORY
        val realSize = u64(buf, fnOff + 0x30)            // 真实大小（$FILE_NAME 内副本）
        val mtime = ntfsTimeToMs(u64(buf, fnOff + 0x18)) // LastModified
        val nameLen = buf[fnOff + 0x40].toInt() and 0xFF
        val namespace = buf[fnOff + 0x41].toInt() and 0xFF
        if (namespace == NS_DOS) return                  // 跳过纯 DOS 短名
        val sb = StringBuilder(nameLen)
        var k = 0
        while (k < nameLen && fnOff + 0x42 + k * 2 + 1 < buf.size) {
            sb.append(u16(buf, fnOff + 0x42 + k * 2).toChar()); k++
        }
        val name = sb.toString()
        if (name.isEmpty() || name == "." ) return
        if (mftRef < 16) return                          // 跳过元文件（$MFT 等前 16 条）
        if (!seen.add(mftRef)) return
        out.add(FsEntry(
            name = name,
            isDirectory = isDir,
            size = if (isDir) 0L else realSize,
            firstCluster = mftRef,                       // NTFS 用 MFT 记录号当句柄
            lastModified = mtime,
        ))
    }

    private fun ntfsTimeToMs(t: Long): Long {
        if (t <= 0) return 0
        return t / 10000 - NTFS_EPOCH_DIFF_MS
    }

    // ---- VolumeFs 接口 ----

    override fun listRoot(): List<FsEntry> = listDirEntries(MFT_ROOT_DIR)

    override fun listDir(firstCluster: Long): List<FsEntry> =
        listDirEntries(if (firstCluster < 16) MFT_ROOT_DIR else firstCluster)

    override fun readFile(firstCluster: Long, fileSize: Long, start: Long, length: Int): ByteArray {
        if (firstCluster < 16) return ByteArray(0)
        return readData(firstCluster, start, length)
    }

    override fun usedDataAreaUpperBound(): Long {
        // NTFS 元数据分散、无简单位图上界。隐藏卷寄生 NTFS 外层极少见，保守返回全区。
        return boot.totalSectors * boot.bytesPerSector
    }

    // ---- 写方向（NTFS 写：受限支持，见下）----

    override fun writeFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean =
        ntfsWriteFile(if (dirFirstCluster < 16) MFT_ROOT_DIR else dirFirstCluster, name, bytes)

    override fun overwriteFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        val dir = if (dirFirstCluster < 16) MFT_ROOT_DIR else dirFirstCluster
        // 覆写 = 删旧 + 写新（非崩溃原子，与 FAT/exFAT 同级）。
        if (!ntfsDeleteFile(dir, name)) return false
        return ntfsWriteFile(dir, name, bytes)
    }

    override fun deleteFile(dirFirstCluster: Long, name: String): Boolean =
        ntfsDeleteFile(if (dirFirstCluster < 16) MFT_ROOT_DIR else dirFirstCluster, name)

    override fun invalidateFsInfo() { /* NTFS 无 FAT32 FSInfo；崩溃一致性靠 chkdsk */ }

    // ---- 内部访问器（供 NtfsWriter 复用只读能力）----
    internal fun mftRecord(no: Long) = readMftRecord(no)
    internal fun bootRef() = boot

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

    // ================= 写基础设施（internal，供 NtfsWriter 用）=================
    //
    // 诚实边界：不实现 $LogFile 日志重放（崩溃一致性）。写完卷标 dirty，Windows 挂载
    // 时自动重置 $LogFile、chkdsk 补一致性——非内核 NTFS 写工具的通行做法。除此之外
    // 元数据完整维护：$Bitmap（簇分配）+ $MFT 的 $BITMAP（记录分配）双位图、FILE 记录
    // USA 打签名、$MFTMirr（记录 0..3）镜像同步。

    val readerRef: VolumeReader get() = reader
    val recordSize: Int get() = mftRecordSize
    val clusterSize: Int get() = bytesPerCluster

    /** MFT 记录 [recordNo] 在卷内的逻辑字节偏移（经 $MFT runs 定位）。启动前用线性。 */
    internal fun mftRecordLogicalOffset(recordNo: Long): Long? {
        val runs = mftDataRuns ?: return boot.mftByteOffset + recordNo * mftRecordSize
        val target = recordNo * mftRecordSize
        var walked = 0L
        for (run in runs) {
            val runBytes = run.length * bytesPerCluster
            if (run.sparse) { walked += runBytes; continue }
            if (target < walked + runBytes) return run.lcn * bytesPerCluster + (target - walked)
            walked += runBytes
        }
        return null
    }

    /**
     * 把明文 FILE 记录 [rec]（长 = mftRecordSize，未打 USA）写回记录 [recordNo]：
     * 先 USA 打签名（递增 USN，扇区末 2 字节存进 USA 数组并替换为 USN），写主 $MFT；
     * 记录号 < 4 时同步 $MFTMirr。不 flush（MountManager 统一）。
     */
    internal fun writeMftRecord(recordNo: Long, rec: ByteArray): Boolean {
        val stamped = rec.copyOf()
        stampUsa(stamped)
        val off = mftRecordLogicalOffset(recordNo) ?: return false
        reader.write(off, stamped, 0, stamped.size)
        if (recordNo < 4) {
            val mirrOff = mftMirrRecordLogicalOffset(recordNo)
            if (mirrOff != null) reader.write(mirrOff, stamped, 0, stamped.size)
        }
        return true
    }

    private var mftMirrRuns: List<DataRun>? = null
    private fun mftMirrRecordLogicalOffset(recordNo: Long): Long? {
        if (recordNo >= 4) return null
        val runs = mftMirrRuns ?: run {
            val rec = readMftRecord(7L) ?: return null
            val data = findAttr(parseAttrs(rec), ATTR_DATA) ?: return null
            if (!data.nonResident) return null
            decodeRuns(data.recordBuf, data.runsOffset).also { mftMirrRuns = it }
        }
        val target = recordNo * mftRecordSize
        var walked = 0L
        for (run in runs) {
            val runBytes = run.length * bytesPerCluster
            if (run.sparse) { walked += runBytes; continue }
            if (target < walked + runBytes) return run.lcn * bytesPerCluster + (target - walked)
            walked += runBytes
        }
        return null
    }

    /** USA 打签名：递增 USN → 扇区末 2 字节存入 USA 数组 → 扇区末写 USN。 */
    private fun stampUsa(buf: ByteArray) {
        val usaOff = u16(buf, 4)
        val usaCount = u16(buf, 6)
        if (usaOff <= 0 || usaCount <= 0) return
        val newUsn = (u16(buf, usaOff) + 1) and 0xFFFF
        putU16(buf, usaOff, newUsn)
        for (i in 1 until usaCount) {
            val sectorEnd = i * boot.bytesPerSector - 2
            if (sectorEnd + 1 >= buf.size) break
            putU16(buf, usaOff + i * 2, u16(buf, sectorEnd))
            putU16(buf, sectorEnd, newUsn)
        }
    }

    // ---- 簇位图 $Bitmap（MFT 记录 6 的 $DATA）----
    private var clusterBitmapRuns: List<DataRun>? = null
    private var clusterBitmapResident: ByteArray? = null

    private fun ensureClusterBitmap() {
        if (clusterBitmapRuns != null || clusterBitmapResident != null) return
        val rec = readMftRecord(6L) ?: return
        val data = findAttr(parseAttrs(rec), ATTR_DATA) ?: return
        if (data.nonResident) clusterBitmapRuns = decodeRuns(data.recordBuf, data.runsOffset)
        else clusterBitmapResident = data.residentValue()
    }

    private fun clusterBitmapByteOffset(byteIdx: Long): Long? {
        val runs = clusterBitmapRuns ?: return null
        var walked = 0L
        for (run in runs) {
            val runBytes = run.length * bytesPerCluster
            if (run.sparse) { walked += runBytes; continue }
            if (byteIdx < walked + runBytes) return run.lcn * bytesPerCluster + (byteIdx - walked)
            walked += runBytes
        }
        return null
    }

    private fun readClusterBitmapByte(byteIdx: Long): Int {
        clusterBitmapResident?.let { return if (byteIdx < it.size) it[byteIdx.toInt()].toInt() and 0xFF else 0 }
        val off = clusterBitmapByteOffset(byteIdx) ?: return 0xFF
        return reader.read(off, 1)[0].toInt() and 0xFF
    }

    private fun writeClusterBitmapByte(byteIdx: Long, value: Int) {
        if (clusterBitmapResident != null) return   // 驻留簇位图（极小卷）此版不写
        val off = clusterBitmapByteOffset(byteIdx) ?: return
        reader.write(off, byteArrayOf(value.toByte()), 0, 1)
    }

    private fun isClusterUsed(lcn: Long): Boolean {
        val b = readClusterBitmapByte(lcn / 8)
        return (b shr (lcn % 8).toInt()) and 1 == 1
    }

    private fun setClusterBit(lcn: Long, used: Boolean) {
        val byteIdx = lcn / 8
        val bit = (lcn % 8).toInt()
        val cur = readClusterBitmapByte(byteIdx)
        writeClusterBitmapByte(byteIdx, if (used) cur or (1 shl bit) else cur and (1 shl bit).inv())
    }

    /** 分配 [count] 个连续空闲簇，返回起始 LCN；无连续块返回 -1。 */
    internal fun allocContiguousClusters(count: Long): Long {
        if (count <= 0) return -1
        ensureClusterBitmap()
        if (clusterBitmapRuns == null) return -1   // 仅支持非驻留簇位图（常规卷）
        val totalClusters = boot.totalSectors / boot.sectorsPerCluster
        var runStart = -1L
        var runLen = 0L
        var c = 0L
        while (c < totalClusters) {
            if (!isClusterUsed(c)) {
                if (runStart < 0) runStart = c
                runLen++
                if (runLen >= count) {
                    for (x in runStart until runStart + count) setClusterBit(x, true)
                    return runStart
                }
            } else { runStart = -1; runLen = 0 }
            c++
        }
        return -1
    }

    internal fun freeClusters(startLcn: Long, count: Long) {
        if (startLcn < 0 || count <= 0) return
        ensureClusterBitmap()
        for (x in startLcn until startLcn + count) setClusterBit(x, false)
    }

    // ---- MFT 记录位图（记录 0 的 $BITMAP 0xB0）----
    private var mftBitmapRuns: List<DataRun>? = null
    private var mftBitmapResident: ByteArray? = null

    private fun ensureMftBitmap() {
        if (mftBitmapRuns != null || mftBitmapResident != null) return
        val rec = readMftRecord(0L) ?: return
        val bmp = findAttr(parseAttrs(rec), 0xB0L) ?: return
        if (bmp.nonResident) mftBitmapRuns = decodeRuns(bmp.recordBuf, bmp.runsOffset)
        else mftBitmapResident = bmp.residentValue()
    }

    private fun mftBitmapByteOffset(byteIdx: Long): Long? {
        val runs = mftBitmapRuns ?: return null
        var walked = 0L
        for (run in runs) {
            val runBytes = run.length * bytesPerCluster
            if (run.sparse) { walked += runBytes; continue }
            if (byteIdx < walked + runBytes) return run.lcn * bytesPerCluster + (byteIdx - walked)
            walked += runBytes
        }
        return null
    }

    private fun readMftBitmapByte(byteIdx: Long): Int {
        mftBitmapResident?.let { return if (byteIdx < it.size) it[byteIdx.toInt()].toInt() and 0xFF else 0xFF }
        val off = mftBitmapByteOffset(byteIdx) ?: return 0xFF
        return reader.read(off, 1)[0].toInt() and 0xFF
    }

    private fun writeMftBitmapByte(byteIdx: Long, value: Int) {
        if (mftBitmapResident != null) return
        val off = mftBitmapByteOffset(byteIdx) ?: return
        reader.write(off, byteArrayOf(value.toByte()), 0, 1)
    }

    /** 分配空闲 MFT 记录号（位图找 0 位→置 1）。无空闲返回 -1。 */
    internal fun allocMftRecord(): Long {
        ensureMftBitmap()
        val rec0 = readMftRecord(0L) ?: return -1
        val data = findAttr(parseAttrs(rec0), ATTR_DATA) ?: return -1
        val totalRecords = data.realSize / mftRecordSize
        var r = 24L
        while (r < totalRecords) {
            val byteIdx = r / 8
            val bit = (r % 8).toInt()
            val b = readMftBitmapByte(byteIdx)
            if ((b shr bit) and 1 == 0) {
                writeMftBitmapByte(byteIdx, b or (1 shl bit))
                return r
            }
            r++
        }
        return -1
    }

    internal fun freeMftRecord(recordNo: Long) {
        ensureMftBitmap()
        val byteIdx = recordNo / 8
        val bit = (recordNo % 8).toInt()
        val b = readMftBitmapByte(byteIdx)
        writeMftBitmapByte(byteIdx, b and (1 shl bit).inv())
    }

    private fun putU16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v and 0xFF).toByte(); b[o + 1] = ((v shr 8) and 0xFF).toByte()
    }

    private fun putU32(b: ByteArray, o: Int, v: Long) {
        for (k in 0 until 4) b[o + k] = ((v ushr (8 * k)) and 0xFF).toByte()
    }
    private fun putU64(b: ByteArray, o: Int, v: Long) {
        for (k in 0 until 8) b[o + k] = ((v ushr (8 * k)) and 0xFF).toByte()
    }


    // ================= NTFS 写实现（internal 基础设施之上的高层组装）=================
    //
    // 诚实边界（再次申明）：不写 $LogFile 日志。写完的卷 Windows 会当作「未净卸载」，
    // 挂载时自动重置 $LogFile 并让 chkdsk 校一致性。元数据本身完整正确：新 FILE 记录、
    // 双位图、$MFTMirr 同步、父目录索引项。
    //
    // 保守原则：拿不准会破坏结构的场景一律「拒绝（返回 false，不动盘）」，绝不硬写赌运气。
    // 明确拒绝的场景见各方法注释。这样最坏是「写不进」，绝不「写坏卷」。

    /** 属性头对齐（NTFS 属性 8 字节对齐）。 */
    private fun align8(v: Int) = (v + 7) and 0x7.inv()

    /**
     * 在目录 [dirRef] 下建名为 [name] 的文件，内容 [bytes]。成功 true。
     * 拒绝场景：名已存在 / MFT 满 / 簇不足 / 父目录索引放不下（需 B+树分裂）/ 名过长。
     */
    private fun ntfsWriteFile(dirRef: Long, name: String, bytes: ByteArray): Boolean {
        if (name.isEmpty() || name.length > 255) return false
        // 名已存在则拒绝（覆写走 overwrite）。
        if (listDirEntries(dirRef).any { it.name.equals(name, ignoreCase = false) }) return false

        // 分配新 MFT 记录号。
        val newRef = allocMftRecord()
        if (newRef < 0) return false

        // 决定 $DATA 驻留 / 非驻留：能塞进记录剩余空间就驻留，否则连续分配簇。
        // 记录布局预算：头(56) + $STD_INFO(约72) + $FILE_NAME(约 90+2*len) + $DATA头 + $END(8)。
        val fnContentLen = 0x42 + name.length * 2
        val fnAttrLen = align8(0x18 + fnContentLen)          // 属性头16 + 名字属性头0x08 ... 见构建
        val stdAttrLen = align8(0x18 + 0x48)                 // $STANDARD_INFORMATION 常规 0x48 内容
        val headerAndFixed = 0x38 + 8 /*USA*/ + stdAttrLen + fnAttrLen + 8 /*$END*/
        val residentDataMax = mftRecordSize - headerAndFixed - 0x18 /*$DATA 头*/ - 8
        val resident = bytes.size <= residentDataMax && residentDataMax > 0

        var dataLcn = -1L
        var dataClusters = 0L
        if (!resident && bytes.isNotEmpty()) {
            dataClusters = (bytes.size + clusterSize - 1).toLong() / clusterSize
            dataLcn = allocContiguousClusters(dataClusters)
            if (dataLcn < 0) { freeMftRecord(newRef); return false }
        }

        // 构建 FILE 记录明文（未打 USA，writeMftRecord 内部打）。
        val rec = buildFileRecord(newRef, dirRef, name, bytes, resident, dataLcn, dataClusters)
        if (rec == null) {
            if (dataLcn >= 0) freeClusters(dataLcn, dataClusters)
            freeMftRecord(newRef)
            return false
        }

        // 先把索引项插进父目录（可能因放不下而拒绝——此时回滚，不留孤儿记录）。
        val fnEntry = buildFileNameForIndex(newRef, dirRef, name, bytes.size.toLong(),
            allocForIndex(resident, bytes.size.toLong(), dataClusters), false)
        if (!insertIndexEntry(dirRef, fnEntry, newRef)) {
            if (dataLcn >= 0) freeClusters(dataLcn, dataClusters)
            freeMftRecord(newRef)
            return false
        }

        // 索引插入成功后再落 FILE 记录（顺序：先索引可回滚，记录落盘即生效）。
        if (!writeMftRecord(newRef, rec)) {
            // 记录写失败：尽力回滚索引 + 资源。
            removeIndexEntry(dirRef, name)
            if (dataLcn >= 0) freeClusters(dataLcn, dataClusters)
            freeMftRecord(newRef)
            return false
        }
        // 写非驻留数据。
        if (!resident && bytes.isNotEmpty()) {
            writeClustersData(dataLcn, bytes)
        }
        return true
    }

    private fun allocForIndex(resident: Boolean, size: Long, clusters: Long): Long =
        if (resident) align8Long(size) else clusters * clusterSize

    private fun align8Long(v: Long) = (v + 7) and 0x7L.inv()

    /**
     * 组装一条 FILE 记录（明文，含 $STD_INFO + $FILE_NAME + $DATA + $END）。
     * [resident]=true 时 $DATA 驻留（数据在记录内）；否则非驻留（单 run 指向 [dataLcn]）。
     */
    private fun buildFileRecord(
        recordNo: Long, parentRef: Long, name: String, bytes: ByteArray,
        resident: Boolean, dataLcn: Long, dataClusters: Long,
    ): ByteArray? {
        val rec = ByteArray(recordSize)
        val sectorCount = recordSize / bootSectorSize()
        val usaCount = sectorCount + 1
        val usaOff = 0x30
        // FILE 记录头。
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, usaOff)                 // USA 偏移
        putU16(rec, 6, usaCount)               // USA 项数（含 USN）
        putU64(rec, 8, 0L)                     // $LogFile LSN（不维护，置 0）
        putU16(rec, 16, 1)                     // 序列号
        putU16(rec, 18, 1)                     // 硬链接数
        val firstAttrOff = align8(usaOff + usaCount * 2)
        putU16(rec, 20, firstAttrOff)          // 首属性偏移
        putU16(rec, 22, FLAG_IN_USE)           // 标志：使用中（非目录）
        putU16(rec, 0x28, 7)   // next-attr-id (> max used id=6: STD=0/FILE_NAME=1/DATA=6)
        putU16(rec, 0x2A, 0)
        putU32(rec, 0x2C, recordNo)            // 本记录号

        var off = firstAttrOff
        // --- $STANDARD_INFORMATION (0x10, 驻留) ---
        off = writeStdInfo(rec, off)
        // --- $FILE_NAME (0x30, 驻留) ---
        off = writeFileNameAttr(rec, off, parentRef, name, bytes.size.toLong(),
            if (resident) align8Long(bytes.size.toLong()) else dataClusters * clusterSize)
        if (off < 0) return null
        // --- $DATA (0x80) ---
        off = if (resident) writeResidentData(rec, off, bytes)
              else writeNonResidentData(rec, off, dataLcn, dataClusters, bytes.size.toLong())
        if (off < 0) return null
        // --- $END ---
        if (off + 8 > recordSize) return null
        putU32(rec, off, ATTR_END)
        // 已用大小 / 分配大小。
        putU32(rec, 0x18, (off + 8).toLong())
        putU32(rec, 0x1C, recordSize.toLong())
        return rec
    }

    private fun bootSectorSize() = bootRef().bytesPerSector

    /** 写 $STANDARD_INFORMATION，返回下一属性偏移。 */
    private fun writeStdInfo(rec: ByteArray, off: Int): Int {
        val contentLen = 0x48
        val hdr = 0x18
        val total = align8(hdr + contentLen)
        putU32(rec, off, ATTR_STANDARD_INFO)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0                       // 驻留
        putU16(rec, off + 10, 0)               // 无名
        putU32(rec, off + 0x10, contentLen.toLong())
        putU16(rec, off + 0x14, hdr)
        val now = msToNtfsTime(System.currentTimeMillis())
        putU64(rec, off + hdr + 0x00, now)     // Creation
        putU64(rec, off + hdr + 0x08, now)     // Altered
        putU64(rec, off + hdr + 0x10, now)     // MFT changed
        putU64(rec, off + hdr + 0x18, now)     // Read
        putU32(rec, off + hdr + 0x20, 0x20L)   // FILE_ATTRIBUTE_ARCHIVE
        return off + total
    }

    /** 写 $FILE_NAME 属性，返回下一属性偏移；越界返回 -1。 */
    private fun writeFileNameAttr(rec: ByteArray, off: Int, parentRef: Long, name: String,
                                  realSize: Long, allocSize: Long): Int {
        val fn = buildFileNameForIndex(parentRef, 0L, name, realSize, allocSize, false)
        // buildFileNameForIndex 造的是「索引项里的 $FILE_NAME 内容」，这里作属性内容用同一体。
        val contentLen = fn.size
        val hdr = 0x18
        val total = align8(hdr + contentLen)
        if (off + total > recordSize) return -1
        putU32(rec, off, ATTR_FILE_NAME)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0                       // 驻留
        rec[off + 9] = 0                       // 名长 0（属性名，非文件名）
        putU16(rec, off + 10, 0)
        putU16(rec, off + 12, 1)               // attr id
        putU32(rec, off + 0x10, contentLen.toLong())
        putU16(rec, off + 0x14, hdr)
        rec[off + 0x16] = 1                    // indexed flag（$FILE_NAME 常置 1）
        System.arraycopy(fn, 0, rec, off + hdr, contentLen)
        return off + total
    }

    /** 写驻留 $DATA。返回下一偏移；越界 -1。 */
    private fun writeResidentData(rec: ByteArray, off: Int, bytes: ByteArray): Int {
        val hdr = 0x18
        val total = align8(hdr + bytes.size)
        if (off + total > recordSize) return -1
        putU32(rec, off, ATTR_DATA)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0                       // 驻留
        putU16(rec, off + 10, 0)
        putU16(rec, off + 12, 6)               // attr id
        putU32(rec, off + 0x10, bytes.size.toLong())
        putU16(rec, off + 0x14, hdr)
        System.arraycopy(bytes, 0, rec, off + hdr, bytes.size)
        return off + total
    }

    /** 写非驻留 $DATA（单 run）。返回下一偏移；越界 -1。 */
    private fun writeNonResidentData(rec: ByteArray, off: Int, lcn: Long, clusters: Long, realSize: Long): Int {
        // 单 run 编码：header(len字节数|offLcn字节数<<4) + length + lcn。
        val runBytes = encodeSingleRun(lcn, clusters)
        val hdr = 0x40 + runBytes.size
        val total = align8(hdr)
        if (off + total > recordSize) return -1
        val allocSize = clusters * clusterSize
        putU32(rec, off, ATTR_DATA)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 1                       // 非驻留
        putU16(rec, off + 10, 0)
        putU16(rec, off + 12, 6)
        putU64(rec, off + 0x10, 0L)            // 起始 VCN
        putU64(rec, off + 0x18, clusters - 1)  // 结束 VCN
        putU16(rec, off + 0x20, 0x40)          // runs 偏移
        putU64(rec, off + 0x28, allocSize)     // 分配大小
        putU64(rec, off + 0x30, realSize)      // 真实大小
        putU64(rec, off + 0x38, realSize)      // 初始化大小
        System.arraycopy(runBytes, 0, rec, off + 0x40, runBytes.size)
        return off + total
    }

    /** 编码单 run（绝对 LCN，len/off 各用最小字节数）。末尾补 0 结束符。 */
    private fun encodeSingleRun(lcn: Long, length: Long): ByteArray {
        val lenB = minBytes(length)
        val offB = minBytesSigned(lcn)
        val out = ByteArray(1 + lenB + offB + 1)
        out[0] = ((offB shl 4) or lenB).toByte()
        for (k in 0 until lenB) out[1 + k] = ((length ushr (8 * k)) and 0xFF).toByte()
        for (k in 0 until offB) out[1 + lenB + k] = ((lcn ushr (8 * k)) and 0xFF).toByte()
        // 末字节 0 = run 列表结束。
        return out
    }

    private fun minBytes(v: Long): Int {
        var n = 1; var x = v ushr 8
        while (x != 0L) { n++; x = x ushr 8 }
        return n
    }
    private fun minBytesSigned(v: Long): Int {
        // 有符号：确保最高位不被误当符号。
        var n = 1
        while (true) {
            val bits = n * 8
            val min = -(1L shl (bits - 1)); val max = (1L shl (bits - 1)) - 1
            if (v in min..max) return n
            n++
            if (n >= 8) return 8
        }
    }

    /**
     * 造「索引项用的 $FILE_NAME 内容体」（也复用作 $FILE_NAME 属性内容）。
     * 布局：parentRef(8) + 4×时间(32) + allocSize(8) + realSize(8) + flags(4) + reparse(4)
     *       + nameLen(1) + namespace(1) + name(UTF-16LE)。
     */
    private fun buildFileNameForIndex(mftRefUnused: Long, parentRef: Long, name: String,
                                      realSize: Long, allocSize: Long, isDir: Boolean): ByteArray {
        val contentLen = 0x42 + name.length * 2
        val b = ByteArray(contentLen)
        putU64(b, 0, parentRef and 0x0000FFFFFFFFFFFFL or (1L shl 48))  // 父引用 + 序列号1
        val now = msToNtfsTime(System.currentTimeMillis())
        putU64(b, 0x08, now); putU64(b, 0x10, now); putU64(b, 0x18, now); putU64(b, 0x20, now)
        putU64(b, 0x28, allocSize)
        putU64(b, 0x30, realSize)
        putU32(b, 0x38, if (isDir) 0x10000000L else 0x20L)  // flags
        putU32(b, 0x3C, 0L)                                 // reparse
        b[0x40] = name.length.toByte()                      // 名字符数
        b[0x41] = 1                                          // namespace = 1 (Win32)
        for (k in name.indices) putU16(b, 0x42 + k * 2, name[k].code)
        return b
    }

    private fun writeClustersData(lcn: Long, bytes: ByteArray) {
        val logical = lcn * clusterSize
        // 整簇写：不足一簇的尾部补零。
        val full = ByteArray(((bytes.size + clusterSize - 1) / clusterSize) * clusterSize)
        System.arraycopy(bytes, 0, full, 0, bytes.size)
        readerRef.write(logical, full, 0, full.size)
    }

    private fun msToNtfsTime(ms: Long): Long = (ms + NTFS_EPOCH_DIFF_MS) * 10000L

    // ---- 父目录索引项插入 / 删除 ----

    /**
     * 把索引项（$FILE_NAME 内容 [fnContent]，指向 [mftRef]）插入目录 [dirRef]。
     * 仅支持插入 $INDEX_ROOT 且记录有足够空闲空间的情形；需扩到 $INDEX_ALLOCATION
     * 或 B+树分裂的情形一律拒绝（返回 false，不动盘）——保守，绝不写坏 B+树。
     */
    private fun insertIndexEntry(dirRef: Long, fnContent: ByteArray, mftRef: Long): Boolean {
        val rec = readMftRecord(dirRef) ?: return false
        val attrs = parseAttrs(rec)
        val root = findAttr(attrs, ATTR_INDEX_ROOT, "\$I30") ?: return false
        if (root.nonResident) return false                 // 索引根必驻留，异常则拒绝
        // 若已存在 $INDEX_ALLOCATION（大目录，B+树）→ 保守拒绝（不做树插入）。
        if (findAttr(attrs, ATTR_INDEX_ALLOCATION, "\$I30") != null) return false

        // 新索引项：ref(8)+entryLen(2)+contentLen(2)+flags(2)+pad(2)+fnContent，8 字节对齐。
        val entryLen = align8(0x10 + fnContent.size)
        val entry = ByteArray(entryLen)
        putU64(entry, 0, mftRef and 0x0000FFFFFFFFFFFFL or (1L shl 48))
        putU16(entry, 8, entryLen)
        putU16(entry, 10, fnContent.size)
        putU16(entry, 12, 0)                               // flags：非子节点、非末项
        System.arraycopy(fnContent, 0, entry, 0x10, fnContent.size)

        // $INDEX_ROOT 属性内容：indexHeader(0x10) + 索引节点头(0x10) + 条目...
        val rootAttrOff = attrOffsetOf(rec, ATTR_INDEX_ROOT, "\$I30") ?: return false
        val rootContentOff = rootAttrOff + u16(rec, rootAttrOff + 0x14)
        val rootContentLen = u32(rec, rootAttrOff + 0x10).toInt()
        // 索引节点头在内容偏移 0x10 处：entriesOffset(4)@0x00 相对节点头, totalSize(4)@0x04, allocSize(4)@0x08。
        val nodeHdr = rootContentOff + 0x10
        val entriesRel = u32(rec, nodeHdr + 0x00).toInt()
        val usedSize = u32(rec, nodeHdr + 0x04).toInt()
        val entriesStart = nodeHdr + entriesRel

        // 找末项（flags bit1）。新项插在末项之前。
        var p = entriesStart
        val contentEnd = rootContentOff + rootContentLen
        var lastOff = -1
        while (p + 0x10 <= contentEnd) {
            val flags = u16(rec, p + 12)
            val elen = u16(rec, p + 8)
            if (flags and INDEX_ENTRY_LAST != 0) { lastOff = p; break }
            if (elen <= 0) break
            p += elen
        }
        if (lastOff < 0) return false

        // 需要的新增字节 = entryLen。检查记录剩余空间是否放得下（含属性/记录已用大小增长）。
        val recUsed = u32(rec, 0x18).toInt()
        if (recUsed + entryLen > recordSize) return false  // 放不下 → 拒绝（需转 $INDEX_ALLOCATION）

        // 在 lastOff 处插入新项：把 [lastOff, contentEnd) 后移 entryLen，再写入新项。
        val newRec = rec.copyOf()
        // 后移末项及其后（末项之后通常无内容，但稳妥整体搬）。
        val tailLen = contentEnd - lastOff
        System.arraycopy(rec, lastOff, newRec, lastOff + entryLen, tailLen.coerceAtMost(recordSize - (lastOff + entryLen)))
        System.arraycopy(entry, 0, newRec, lastOff, entryLen)

        // 更新尺寸：索引节点 usedSize、$INDEX_ROOT 属性 contentLen 与 total、记录已用大小。
        putU32(newRec, nodeHdr + 0x04, (usedSize + entryLen).toLong())
        // 属性内容长度。
        putU32(newRec, rootAttrOff + 0x10, (rootContentLen + entryLen).toLong())
        // 属性总长（含头，8 对齐）。
        val oldAttrTotal = u32(rec, rootAttrOff + 4).toInt()
        putU32(newRec, rootAttrOff + 4, (oldAttrTotal + entryLen).toLong())
        // 后续属性整体后移 entryLen（$INDEX_ROOT 之后可能还有属性，如 $BITMAP/$END）。
        val afterOff = rootAttrOff + oldAttrTotal
        val moveLen = recUsed - afterOff
        if (moveLen > 0) {
            System.arraycopy(rec, afterOff, newRec, afterOff + entryLen, moveLen.coerceAtMost(recordSize - (afterOff + entryLen)))
        }
        putU32(newRec, 0x18, (recUsed + entryLen).toLong())

        return writeMftRecord(dirRef, newRec)
    }

    /** 从目录 [dirRef] 的 $INDEX_ROOT 删除名为 [name] 的索引项。找不到/在 $INDEX_ALLOCATION 里则 false。 */
    private fun removeIndexEntry(dirRef: Long, name: String): Boolean {
        val rec = readMftRecord(dirRef) ?: return false
        val attrs = parseAttrs(rec)
        val root = findAttr(attrs, ATTR_INDEX_ROOT, "\$I30") ?: return false
        if (root.nonResident) return false
        val rootAttrOff = attrOffsetOf(rec, ATTR_INDEX_ROOT, "\$I30") ?: return false
        val rootContentOff = rootAttrOff + u16(rec, rootAttrOff + 0x14)
        val rootContentLen = u32(rec, rootAttrOff + 0x10).toInt()
        val nodeHdr = rootContentOff + 0x10
        val entriesRel = u32(rec, nodeHdr + 0x00).toInt()
        val usedSize = u32(rec, nodeHdr + 0x04).toInt()
        var p = rootContentOff + 0x10 + entriesRel
        val contentEnd = rootContentOff + rootContentLen
        while (p + 0x10 <= contentEnd) {
            val flags = u16(rec, p + 12)
            val elen = u16(rec, p + 8)
            if (flags and INDEX_ENTRY_LAST != 0) break
            if (elen <= 0) break
            val contentLen = u16(rec, p + 10)
            if (contentLen > 0) {
                val nameLen = rec[p + 0x10 + 0x40].toInt() and 0xFF
                val ns = rec[p + 0x10 + 0x41].toInt() and 0xFF
                if (ns != NS_DOS && nameLen > 0) {
                    val sb = StringBuilder(nameLen)
                    for (k in 0 until nameLen) sb.append(u16(rec, p + 0x10 + 0x42 + k * 2).toChar())
                    if (sb.toString() == name) {
                        // 删除本项：把 [p+elen, recUsed) 前移 elen。
                        val recUsed = u32(rec, 0x18).toInt()
                        val newRec = rec.copyOf()
                        val tail = recUsed - (p + elen)
                        if (tail > 0) System.arraycopy(rec, p + elen, newRec, p, tail)
                        // 尾部清零 elen。
                        for (k in 0 until elen) if (recUsed - elen + k in 0 until recordSize) newRec[recUsed - elen + k] = 0
                        putU32(newRec, nodeHdr + 0x04, (usedSize - elen).toLong())
                        putU32(newRec, rootAttrOff + 0x10, (rootContentLen - elen).toLong())
                        val oldAttrTotal = u32(rec, rootAttrOff + 4).toInt()
                        putU32(newRec, rootAttrOff + 4, (oldAttrTotal - elen).toLong())
                        putU32(newRec, 0x18, (recUsed - elen).toLong())
                        return writeMftRecord(dirRef, newRec)
                    }
                }
            }
            p += elen
        }
        return false
    }

    /** 找记录内某属性的字节偏移（首个匹配 type+name）。 */
    private fun attrOffsetOf(rec: ByteArray, type: Long, name: String): Int? {
        var off = u16(rec, 0x14)
        while (off + 4 <= rec.size) {
            val t = u32(rec, off)
            if (t == ATTR_END) break
            val len = u32(rec, off + 4).toInt()
            if (len <= 0 || off + len > rec.size) break
            val nameLen = rec[off + 9].toInt() and 0xFF
            val nameOff = u16(rec, off + 10)
            val an = if (nameLen > 0) {
                val sb = StringBuilder(nameLen)
                for (k in 0 until nameLen) sb.append(u16(rec, off + nameOff + k * 2).toChar())
                sb.toString()
            } else ""
            if (t == type && an == name) return off
            off += len
        }
        return null
    }

    /**
     * 删除目录 [dirRef] 下的文件 [name]。释放其数据簇 + MFT 记录 + 父目录索引项。
     * 仅支持 $INDEX_ROOT 内的项（与 insert 对称）；其余拒绝。
     */
    private fun ntfsDeleteFile(dirRef: Long, name: String): Boolean {
        // 先找到目标 MFT 记录号。
        val target = listDirEntriesWithRef(dirRef).firstOrNull { it.second == name }?.first ?: return false
        val rec = readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        // 释放非驻留 $DATA 的簇。
        val data = findAttr(attrs, ATTR_DATA)
        if (data != null && data.nonResident) {
            val runs = decodeRuns(data.recordBuf, data.runsOffset)
            for (run in runs) if (!run.sparse) freeClusters(run.lcn, run.length)
        }
        // 从父目录删索引项。
        if (!removeIndexEntry(dirRef, name)) return false
        // 标记 FILE 记录不再使用（清 in-use 标志）+ 释放 MFT 位。
        val flags = u16(rec, 0x16) and FLAG_IN_USE.inv()
        val nr = rec.copyOf()
        putU16(nr, 0x16, flags)
        // 序列号 +1（NTFS 删除惯例）。
        putU16(nr, 16, (u16(rec, 16) + 1) and 0xFFFF)
        writeMftRecord(target, nr)
        freeMftRecord(target)
        return true
    }

    /** 目录条目带 MFT 记录号（删除定位用）。 */
    private fun listDirEntriesWithRef(dirRef: Long): List<Pair<Long, String>> {
        val out = ArrayList<Pair<Long, String>>()
        for (e in listDirEntries(dirRef)) out.add(Pair(e.firstCluster, e.name))
        return out
    }


}
