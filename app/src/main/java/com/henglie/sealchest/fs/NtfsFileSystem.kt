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

    internal class DataRun(val length: Long, val lcn: Long, val sparse: Boolean)

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
            // M1 修复：$MFTMirr 是 MFT 记录 1，不是记录 7（记录 7 是 $Boot，其 $DATA 指向 LCN 0
            //   引导区）。原读记录 7 → 镜像写会落到引导扇区、毁容器头。当前写路径 recordNo 全≥5
            //   不触发，属潜伏致命；一并修正。
            val rec = readMftRecord(1L) ?: return null
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

    /**
     * 多段簇分配（W6）：碎片化空间写大文件用。先尝试整体连续（最优），失败则逐段凑够 [need] 簇。
     * 返回分配的段列表（每段 DataRun(lcn, length, sparse=false)）；空间不足抛 [VolumeFullException]（已回滚）。
     */
    internal fun allocMultipleClusters(need: Long): List<DataRun> {
        if (need <= 0) return emptyList()
        ensureClusterBitmap()
        if (clusterBitmapRuns == null) throw VolumeFullException()
        // 先试整体连续（最快、最对齐）。
        val contig = allocContiguousClusters(need)
        if (contig >= 0) return listOf(DataRun(need, contig, sparse = false))
        // 分段：线性扫空闲簇，累计到 need。每段尽量长（贪心），段间断开即新段。
        val segs = ArrayList<DataRun>()
        var segStart = -1L
        var segLen = 0L
        var got = 0L
        var c = 0L
        val totalClusters = boot.totalSectors / boot.sectorsPerCluster
        while (c < totalClusters && got < need) {
            if (!isClusterUsed(c)) {
                if (segStart < 0) segStart = c
                segLen++
            } else {
                if (segLen > 0) { segs.add(DataRun(segLen, segStart, sparse = false)); got += segLen; segStart = -1; segLen = 0 }
            }
            c++
        }
        if (segLen > 0) { segs.add(DataRun(segLen, segStart, sparse = false)); got += segLen }
        if (got < need) {
            // 空间不足：回滚已占位。
            for (s in segs) for (x in s.lcn until s.lcn + s.length) setClusterBit(x, false)
            throw VolumeFullException()
        }
        return segs
    }

    /** 释放多段簇（W6，与 allocMultipleClusters 对称）。 */
    internal fun freeMultiClusters(runs: List<DataRun>) {
        for (r in runs) if (!r.sparse) freeClusters(r.lcn, r.length)
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
        var multiRuns: List<DataRun>? = null   // W6 多段路径
        if (!resident && bytes.isNotEmpty()) {
            dataClusters = (bytes.size + clusterSize - 1).toLong() / clusterSize
            // W6：先试连续（dataLcn），失败走多段（multiRuns）。allocMultipleClusters 空间不足抛异常。
            dataLcn = allocContiguousClusters(dataClusters)
            if (dataLcn < 0) {
                multiRuns = allocMultipleClusters(dataClusters)   // 抛 VolumeFullException 或返回段
                dataLcn = -1L   // 走多段路径
            }
        }

        // 构建 FILE 记录明文（未打 USA，writeMftRecord 内部打）。W6：多段走 buildFileRecordMulti。
        val rec = if (multiRuns != null) {
            buildFileRecordMulti(newRef, dirRef, name, bytes, multiRuns, bytes.size.toLong())
        } else {
            buildFileRecord(newRef, dirRef, name, bytes, resident, dataLcn, dataClusters)
        }
        if (rec == null) {
            if (dataLcn >= 0) freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) freeMultiClusters(multiRuns)
            freeMftRecord(newRef)
            return false
        }

        // 先把索引项插进父目录（可能因放不下而拒绝——此时回滚，不留孤儿记录）。
        val fnEntry = buildFileNameForIndex(newRef, dirRef, name, bytes.size.toLong(),
            allocForIndex(resident, bytes.size.toLong(), dataClusters), false)
        if (!insertIndexEntry(dirRef, fnEntry, newRef)) {
            if (dataLcn >= 0) freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) freeMultiClusters(multiRuns)
            freeMftRecord(newRef)
            return false
        }

        // 索引插入成功后再落 FILE 记录（顺序：先索引可回滚，记录落盘即生效）。
        if (!writeMftRecord(newRef, rec)) {
            // 记录写失败：尽力回滚索引 + 资源。
            removeIndexEntry(dirRef, name)
            if (dataLcn >= 0) freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) freeMultiClusters(multiRuns)
            freeMftRecord(newRef)
            return false
        }
        // 写非驻留数据。W6：多段走 writeMultiClustersData。
        if (!resident && bytes.isNotEmpty()) {
            if (multiRuns != null) writeMultiClustersData(multiRuns, bytes)
            else writeClustersData(dataLcn, bytes)
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

    /**
     * 组装 FILE 记录（多段 $DATA，W6）。与 [buildFileRecord] 同布局，仅 $DATA 走多段编码。
     * [runs] 为绝对 LCN 段列表；[realSize] 为真实字节；总簇数 = runs 之和。
     */
    private fun buildFileRecordMulti(
        recordNo: Long, parentRef: Long, name: String, bytes: ByteArray,
        runs: List<DataRun>, realSize: Long,
    ): ByteArray? {
        val rec = ByteArray(recordSize)
        val sectorCount = recordSize / bootSectorSize()
        val usaCount = sectorCount + 1
        val usaOff = 0x30
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, usaOff)
        putU16(rec, 6, usaCount)
        putU64(rec, 8, 0L)
        putU16(rec, 16, 1)
        putU16(rec, 18, 1)
        val firstAttrOff = align8(usaOff + usaCount * 2)
        putU16(rec, 20, firstAttrOff)
        putU16(rec, 22, FLAG_IN_USE)
        putU16(rec, 0x28, 7)
        putU16(rec, 0x2A, 0)
        putU32(rec, 0x2C, recordNo)
        var off = firstAttrOff
        off = writeStdInfo(rec, off)
        val totalClusters = runs.sumOf { it.length }
        off = writeFileNameAttr(rec, off, parentRef, name, realSize, totalClusters * clusterSize)
        if (off < 0) return null
        off = writeNonResidentDataMulti(rec, off, runs, realSize)
        if (off < 0) return null
        if (off + 8 > recordSize) return null
        putU32(rec, off, ATTR_END)
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

    /** 写非驻留 $DATA（多段，W6）。runs 为绝对 LCN 段；realSize=真实字节；总簇数=runs 之和。 */
    private fun writeNonResidentDataMulti(rec: ByteArray, off: Int, runs: List<DataRun>, realSize: Long): Int {
        val runBytes = encodeMultiRun(runs)
        val totalClusters = runs.sumOf { it.length }
        val hdr = 0x40 + runBytes.size
        val total = align8(hdr)
        if (off + total > recordSize) return -1
        val allocSize = totalClusters * clusterSize
        putU32(rec, off, ATTR_DATA)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 1                       // 非驻留
        putU16(rec, off + 10, 0)
        putU16(rec, off + 12, 6)
        putU64(rec, off + 0x10, 0L)            // 起始 VCN
        putU64(rec, off + 0x18, totalClusters - 1)  // 结束 VCN
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

    /**
     * 编码多段 data run（W6）：逐段编码，相对 LCN 偏移；末尾补 0 结束符。
     * 输入为绝对 LCN 段列表，输出 NTFS runlist 字节（小端，相对偏移有符号）。
     */
    private fun encodeMultiRun(runs: List<DataRun>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var prevLcn = 0L
        for (r in runs) {
            if (r.sparse) {
                // 稀疏段：offBytes=0。
                val lenB = minBytes(r.length)
                out.write(((0) or lenB).toByte().toInt())
                for (k in 0 until lenB) out.write(((r.length ushr (8 * k)) and 0xFF).toByte().toInt())
            } else {
                val delta = r.lcn - prevLcn
                val lenB = minBytes(r.length)
                val offB = minBytesSigned(delta)
                out.write(((offB shl 4) or lenB).toByte().toInt())
                for (k in 0 until lenB) out.write(((r.length ushr (8 * k)) and 0xFF).toByte().toInt())
                for (k in 0 until offB) out.write(((delta ushr (8 * k)) and 0xFF).toByte().toInt())
                prevLcn = r.lcn
            }
        }
        out.write(0)   // 结束符
        return out.toByteArray()
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

    /** 写多段簇数据（W6）：按段顺序写，每段内整簇写、尾簇补零。 */
    private fun writeMultiClustersData(runs: List<DataRun>, bytes: ByteArray) {
        var off = 0
        for (r in runs) {
            val segBytes = (r.length * clusterSize).toInt()
            val chunk = minOf(segBytes, bytes.size - off)
            if (chunk <= 0) break
            val logical = r.lcn * clusterSize
            val block = if (chunk == segBytes) bytes.copyOfRange(off, off + chunk)
                        else ByteArray(segBytes).also { System.arraycopy(bytes, off, it, 0, chunk) }
            readerRef.write(logical, block, 0, block.size)
            off += chunk
        }
    }

    private fun msToNtfsTime(ms: Long): Long = (ms + NTFS_EPOCH_DIFF_MS) * 10000L

    // ---- 父目录索引项插入 / 删除（W4/W5：支持 $INDEX_ROOT→$INDEX_ALLOCATION 迁移）----

    /**
     * 把索引项（$FILE_NAME 内容 [fnContent]，指向 [mftRef]）插入目录 [dirRef]。
     * 三条路径：
     * 1. $INDEX_ROOT 有空间 → 直接插入（小目录）
     * 2. $INDEX_ROOT 满且无 $INDEX_ALLOCATION → 迁移到 $INDEX_ALLOCATION（建首 INDX 叶子 + $BITMAP）
     * 3. 已有 $INDEX_ALLOCATION → 插入 INDX 叶子（仅单叶简单树；多叶/需分裂保守拒绝）
     * 保守原则：拿不准一律返回 false 不动盘，绝不写坏 B+树。
     */
    private fun insertIndexEntry(dirRef: Long, fnContent: ByteArray, mftRef: Long): Boolean {
        val rec = readMftRecord(dirRef) ?: return false
        val attrs = parseAttrs(rec)
        val root = findAttr(attrs, ATTR_INDEX_ROOT, "\$I30") ?: return false
        if (root.nonResident) return false
        val newEntry = buildIndexEntry(fnContent, mftRef, hasSubnode = false, isLast = false)

        // 统一走整树重建：收集全树叶子项 → 加新项 → 排序 → 重建（全驻留/2 层自动选）。
        // >2 层 / 解析异常 → collect 返 null → 保守拒绝。
        val collected = collectAllLeafEntries(rec, attrs) ?: return false
        val all = ArrayList(collected)
        all.add(stripToLeafEntry(newEntry))
        all.sortWith(Comparator { a, b -> entryFileName(a).compareTo(entryFileName(b), ignoreCase = true) })
        return rebuildDirIndex(dirRef, all)
    }

    /** 从索引项字节提取 mftRef（低 48 位）。 */
    private fun entryMftRef(entry: ByteArray): Long = u64(entry, 0) and 0x0000FFFFFFFFFFFFL

    /** 构建单条索引项字节。末项+无内容时 contentLen=0。 */
    private fun buildIndexEntry(fnContent: ByteArray, mftRef: Long,
                                hasSubnode: Boolean, isLast: Boolean, subnodeVcn: Long = 0): ByteArray {
        val contentLen = if (isLast && fnContent.isEmpty()) 0 else fnContent.size
        val bodyLen = 0x10 + contentLen + (if (hasSubnode) 8 else 0)
        val entryLen = align8(bodyLen)
        val entry = ByteArray(entryLen)
        putU64(entry, 0, mftRef and 0x0000FFFFFFFFFFFFL or (1L shl 48))
        putU16(entry, 8, entryLen)
        putU16(entry, 10, contentLen)
        var flags = 0
        if (hasSubnode) flags = flags or INDEX_ENTRY_HAS_SUBNODE
        if (isLast) flags = flags or INDEX_ENTRY_LAST
        putU16(entry, 12, flags)
        if (contentLen > 0) System.arraycopy(fnContent, 0, entry, 0x10, contentLen)
        if (hasSubnode) putU64(entry, 0x10 + contentLen, subnodeVcn)
        return entry
    }

    /** 从索引项字节提取文件名（用于排序）。 */
    private fun entryFileName(entry: ByteArray): String {
        val contentLen = u16(entry, 10)
        if (contentLen < 0x42) return ""
        val nameLen = entry[0x10 + 0x40].toInt() and 0xFF
        val sb = StringBuilder(nameLen)
        for (k in 0 until nameLen) sb.append(u16(entry, 0x10 + 0x42 + k * 2).toChar())
        return sb.toString()
    }

    /**
     * 路径 1：试把 [newEntry] 插入 $INDEX_ROOT（末项前）。
     * 有空间返回新记录；放不下返回 null（不动盘）。
     */
    private fun tryInsertRootEntry(rec: ByteArray, newEntry: ByteArray): ByteArray? {
        val rootAttrOff = attrOffsetOf(rec, ATTR_INDEX_ROOT, "\$I30") ?: return null
        val rootContentOff = rootAttrOff + u16(rec, rootAttrOff + 0x14)
        val rootContentLen = u32(rec, rootAttrOff + 0x10).toInt()
        val nodeHdr = rootContentOff + 0x10
        val entriesRel = u32(rec, nodeHdr + 0x00).toInt()
        val usedSize = u32(rec, nodeHdr + 0x04).toInt()
        val entriesStart = nodeHdr + entriesRel

        // H3 修复：按文件名 collation 找正确插入位置（NTFS 大小写不敏感升序），
        //   而非固定插在末项前。对齐 migrateToIndexAllocation / insertIntoIndxLeaf 的 sortWith
        //   (ignoreCase=true)。原实现直插末项前 → chkdsk 报 unordered index + Windows 二分查找可能漏。
        val newName = entryFileName(newEntry)
        var p = entriesStart
        val contentEnd = rootContentOff + rootContentLen
        var insertOff = -1
        while (p + 0x10 <= contentEnd) {
            val flags = u16(rec, p + 12)
            val elen = u16(rec, p + 8)
            if (flags and INDEX_ENTRY_LAST != 0) {
                // 末项：collation 上无更大键项，新项插在末项前。
                if (insertOff < 0) insertOff = p
                break
            }
            if (elen <= 0) break
            // 首个 name > newName 的键项处即插入点（维持升序）。
            if (insertOff < 0 &&
                entryFileName(rec.copyOfRange(p, p + elen)).compareTo(newName, ignoreCase = true) > 0) {
                insertOff = p
            }
            p += elen
        }
        if (insertOff < 0) return null

        val entryLen = newEntry.size
        val recUsed = u32(rec, 0x18).toInt()
        if (recUsed + entryLen > recordSize) return null   // 放不下

        val newRec = rec.copyOf()
        // 后移插入点及其后内容（含末项）。
        val tailLen = contentEnd - insertOff
        System.arraycopy(rec, insertOff, newRec, insertOff + entryLen,
            tailLen.coerceAtMost(recordSize - (insertOff + entryLen)))
        System.arraycopy(newEntry, 0, newRec, insertOff, entryLen)
        // 更新尺寸：索引节点 usedSize、属性 contentLen 与 total、记录已用大小。
        putU32(newRec, nodeHdr + 0x04, (usedSize + entryLen).toLong())
        putU32(newRec, rootAttrOff + 0x10, (rootContentLen + entryLen).toLong())
        val oldAttrTotal = u32(rec, rootAttrOff + 4).toInt()
        putU32(newRec, rootAttrOff + 4, (oldAttrTotal + entryLen).toLong())
        // 后续属性整体后移。
        val afterOff = rootAttrOff + oldAttrTotal
        val moveLen = recUsed - afterOff
        if (moveLen > 0) {
            System.arraycopy(rec, afterOff, newRec, afterOff + entryLen,
                moveLen.coerceAtMost(recordSize - (afterOff + entryLen)))
        }
        putU32(newRec, 0x18, (recUsed + entryLen).toLong())
        return newRec
    }

    /**
     * 路径 2（W4/W5）：$INDEX_ROOT 放不下 → 迁移到 $INDEX_ALLOCATION。
     * 提取现有项 + 新项排序 → 建 INDX 叶子 → 分配 INDX 簇 + $BITMAP 置位
     * → 改写目录 FILE 记录（大索引根 + $INDEX_ALLOCATION + $BITMAP）。
     */
    private fun migrateToIndexAllocation(dirRef: Long, rec: ByteArray, newEntry: ByteArray): Boolean {
        // 收集现有项 + 新项，按名排序（NTFS 大小写不敏感）。
        val entries = ArrayList<ByteArray>()
        entries.addAll(readIndexRootEntriesRaw(rec))
        entries.add(newEntry)
        entries.sortWith(Comparator { a, b ->
            entryFileName(a).compareTo(entryFileName(b), ignoreCase = true)
        })

        // 建 INDX 叶子记录（VCN 0）。
        val indxRec = buildIndxLeafRecord(entries, 0L) ?: return false   // 一个 INDX 放不下 → 需分裂，保守拒绝

        // 分配 INDX 簇（W5：簇位图置位在 allocContiguousClusters 内完成）。
        val idxRecSize = boot.indexRecordSize
        val clusters = ((idxRecSize + clusterSize - 1) / clusterSize).toLong()
        val lcn = allocContiguousClusters(clusters)
        if (lcn < 0) return false

        // 重建目录 FILE 记录：保留所有非索引属性 + 新 $INDEX_ROOT(大索引) + $INDEX_ALLOCATION + $BITMAP。
        val newRec = rebuildDirRecordLargeIndex(rec, lcn, clusters)
        if (newRec == null) {
            freeClusters(lcn, clusters)
            return false
        }

        // 写 INDX 叶子到磁盘（先打 USA 签名）。
        stampUsa(indxRec)
        reader.write(lcn * clusterSize, indxRec, 0, indxRec.size)

        // 写回目录 FILE 记录。
        if (!writeMftRecord(dirRef, newRec)) {
            freeClusters(lcn, clusters)
            return false
        }
        return true
    }

    /**
     * 路径 3（W4）：已有 $INDEX_ALLOCATION → 插入 INDX 叶子。
     * 仅支持单叶简单树（根只有末项→VCN 0 的子节点指针）。多叶树/需分裂保守拒绝。
     */
    private fun insertIntoIndxLeaf(dirRef: Long, rec: ByteArray, attrs: List<Attr>, newEntry: ByteArray): Boolean {
        // 检查根是否单叶树：$INDEX_ROOT 的索引项仅有末项（无键项）。
        val rootEntries = readIndexRootEntriesRaw(rec)
        if (rootEntries.isNotEmpty()) return false   // 根有键项 = 多叶树，保守拒绝

        val alloc = findAttr(attrs, ATTR_INDEX_ALLOCATION, "\$I30") ?: return false
        if (!alloc.nonResident) return false
        val runs = decodeRuns(alloc.recordBuf, alloc.runsOffset)
        val idxRecSize = boot.indexRecordSize

        // 读 VCN 0 的 INDX 叶子。
        val indx = readFromRuns(runs, 0L, idxRecSize) ?: return false
        if (indx.size < 4 || indx[0] != 'I'.code.toByte()) return false
        applyUsaFixup(indx)

        // 提取叶子现有项。
        val nodeHdr = 24
        val entriesRel = u32(indx, nodeHdr + 0x00).toInt()
        val usedSize = u32(indx, nodeHdr + 0x04).toInt()
        var p = nodeHdr + entriesRel
        val entriesEnd = nodeHdr + entriesRel + usedSize
        val leafEntries = ArrayList<ByteArray>()
        while (p + 0x10 <= entriesEnd && p + 0x10 <= indx.size) {
            val flags = u16(indx, p + 12)
            val elen = u16(indx, p + 8)
            if (elen < 0x10) break
            if (flags and INDEX_ENTRY_LAST != 0) break
            leafEntries.add(indx.copyOfRange(p, p + elen))
            p += elen
        }

        // 加入新项排序。
        leafEntries.add(newEntry)
        leafEntries.sortWith(Comparator { a, b ->
            entryFileName(a).compareTo(entryFileName(b), ignoreCase = true)
        })

        // 重建 INDX 叶子（放不下 = 需分裂 → 保守拒绝）。
        val newIndx = buildIndxLeafRecord(leafEntries, 0L) ?: return false

        // 写回：首段须能容纳整个 INDX 记录。
        val firstRun = runs.firstOrNull { !it.sparse } ?: return false
        if (firstRun.length * clusterSize < idxRecSize) return false   // INDX 跨段，保守拒绝
        stampUsa(newIndx)
        reader.write(firstRun.lcn * clusterSize, newIndx, 0, newIndx.size)
        return true
    }

    /** 从 $INDEX_ROOT 提取现有索引项（原始字节，不含末项标记）。 */
    private fun readIndexRootEntriesRaw(rec: ByteArray): List<ByteArray> {
        val rootAttrOff = attrOffsetOf(rec, ATTR_INDEX_ROOT, "\$I30") ?: return emptyList()
        val rootContentOff = rootAttrOff + u16(rec, rootAttrOff + 0x14)
        val nodeHdr = rootContentOff + 0x10
        val entriesRel = u32(rec, nodeHdr + 0x00).toInt()
        val usedSize = u32(rec, nodeHdr + 0x04).toInt()
        var p = nodeHdr + entriesRel
        val entriesEnd = nodeHdr + entriesRel + usedSize
        val out = ArrayList<ByteArray>()
        while (p + 0x10 <= rec.size && p < entriesEnd) {
            val flags = u16(rec, p + 12)
            val elen = u16(rec, p + 8)
            if (elen < 0x10) break
            if (flags and INDEX_ENTRY_LAST != 0) break
            out.add(rec.copyOfRange(p, p + elen))
            p += elen
        }
        return out
    }

    /**
     * 建 INDX 叶子记录（无子节点，flags=0）。[entries] 已排序。
     * 返回 indexRecordSize 字节的完整记录；放不下返回 null。
     */
    private fun buildIndxLeafRecord(entries: List<ByteArray>, vcn: Long): ByteArray? {
        val idxRecSize = boot.indexRecordSize
        val buf = ByteArray(idxRecSize)
        buf[0] = 'I'.code.toByte(); buf[1] = 'N'.code.toByte(); buf[2] = 'D'.code.toByte(); buf[3] = 'X'.code.toByte()
        val sectorSize = boot.bytesPerSector
        val sectorCount = idxRecSize / sectorSize
        val usaCount = sectorCount + 1
        val usaOff = 0x28
        putU16(buf, 4, usaOff)
        putU16(buf, 6, usaCount)
        putU64(buf, 8, 0L)          // $LogFile LSN
        putU64(buf, 0x10, vcn)      // 本记录 VCN

        val nodeHdr = 0x18
        val entriesOff = align8(usaOff + usaCount * 2) - nodeHdr   // 相对 nodeHdr
        putU32(buf, nodeHdr + 0x00, entriesOff.toLong())

        var p = nodeHdr + entriesOff
        for (e in entries) {
            if (p + e.size > idxRecSize) return null
            System.arraycopy(e, 0, buf, p, e.size)
            p += e.size
        }
        // 末项（叶子，无子节点，16 字节）。
        val last = buildIndexEntry(ByteArray(0), 0, hasSubnode = false, isLast = true)
        if (p + last.size > idxRecSize) return null
        System.arraycopy(last, 0, buf, p, last.size)
        p += last.size

        // index_length（INDEX_HEADER+0x04）= 从 INDEX_HEADER(nodeHdr) 起算的已用字节，
        //   含 INDEX_HEADER(0x10) + USA + 全部项（ntfs-3g: "bytes used from allocated_size"）。
        //   原实现只写纯 entries 字节（漏 entries_offset 那段头+USA）→ chkdsk 报 index_length 不符。修为 p-nodeHdr。
        putU32(buf, nodeHdr + 0x04, (p - nodeHdr).toLong())
        putU32(buf, nodeHdr + 0x08, (idxRecSize - nodeHdr).toLong())   // allocatedSize
        putU32(buf, nodeHdr + 0x0C, 0L)                                 // flags = 叶子
        return buf
    }

    /**
     * 重建目录 FILE 记录为大索引：保留所有非索引属性，
     * 新 $INDEX_ROOT（大索引根，仅末项→VCN 0）+ $INDEX_ALLOCATION（runs→[indxLcn]）+ $BITMAP（W5）+ $END。
     */
    private fun rebuildDirRecordLargeIndex(origRec: ByteArray, indxLcn: Long, indxClusters: Long): ByteArray? {
        val rec = ByteArray(recordSize)
        // FILE 头（保留原值）。
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, u16(origRec, 4))     // USA 偏移
        putU16(rec, 6, u16(origRec, 6))     // USA 项数
        putU64(rec, 8, u64(origRec, 8))     // $LogFile LSN
        putU16(rec, 16, u16(origRec, 16))   // 序列号
        putU16(rec, 18, u16(origRec, 18))   // 硬链接数
        val firstAttrOff = u16(origRec, 20)
        putU16(rec, 20, firstAttrOff)
        putU16(rec, 22, u16(origRec, 22))   // 标志（保留：目录=0x02）
        putU32(rec, 0x2C, u32(origRec, 0x2C))   // 本记录号

        var off = firstAttrOff
        // 复制所有非索引属性（跳过 $INDEX_ROOT/$INDEX_ALLOCATION/$BITMAP 带 $I30 名）。
        var attrOff = firstAttrOff
        val origUsed = u32(origRec, 0x18).toInt()
        while (attrOff + 8 <= origUsed && attrOff + 8 <= origRec.size) {
            val type = u32(origRec, attrOff)
            if (type == ATTR_END) break
            val totalLen = u32(origRec, attrOff + 4).toInt()
            if (totalLen <= 0 || attrOff + totalLen > origUsed) break
            val nameLen = origRec[attrOff + 9].toInt() and 0xFF
            val nameOff = u16(origRec, attrOff + 10)
            val an = if (nameLen > 0) {
                val sb = StringBuilder(nameLen)
                for (k in 0 until nameLen) sb.append(u16(origRec, attrOff + nameOff + k * 2).toChar())
                sb.toString()
            } else ""
            val isIndexAttr = (type == ATTR_INDEX_ROOT || type == ATTR_INDEX_ALLOCATION || type == 0xB0L) && an == "\$I30"
            if (!isIndexAttr) {
                if (off + totalLen > recordSize) return null
                System.arraycopy(origRec, attrOff, rec, off, totalLen)
                off += totalLen
            }
            attrOff += totalLen
        }

        // 属性 id：复用原 $INDEX_ROOT 的 id；新属性用原 next-attr-id 起。
        val origRootOff = attrOffsetOf(origRec, ATTR_INDEX_ROOT, "\$I30")
        val rootAttrId = if (origRootOff != null) u16(origRec, origRootOff + 0x0C) else 2
        val allocAttrId = u16(origRec, 0x28)
        val bmpAttrId = allocAttrId + 1

        // 新 $INDEX_ROOT（大索引根）。
        off = writeLargeIndexRootAttr(rec, off, rootAttrId)
        if (off < 0) return null
        // $INDEX_ALLOCATION（非驻留 → INDX 簇）。
        off = writeIndexAllocationAttr(rec, off, indxLcn, indxClusters, allocAttrId)
        if (off < 0) return null
        // $BITMAP（W5：INDX 记录位图，VCN 0 已用）。
        off = writeIndexBitmapAttr(rec, off, bmpAttrId)
        if (off < 0) return null
        // $END
        if (off + 8 > recordSize) return null
        putU32(rec, off, ATTR_END)
        putU32(rec, 0x18, (off + 8).toLong())
        putU32(rec, 0x1C, recordSize.toLong())
        putU16(rec, 0x28, (bmpAttrId + 1) and 0xFFFF)   // next-attr-id
        return rec
    }

    /** 写大索引 $INDEX_ROOT 属性（仅末项→VCN 0），返回下一偏移；越界 -1。 */
    private fun writeLargeIndexRootAttr(rec: ByteArray, off: Int, attrId: Int): Int {
        val contentLen = 0x38   // INDEX_ROOT头(0x10) + INDEX_HEADER(0x10) + 末项(0x18)
        val nameLen = 4
        val nameOff = 0x18
        val valOff = nameOff + nameLen * 2   // 0x20
        val total = align8(valOff + contentLen)
        if (off + total > recordSize) return -1
        putU32(rec, off, ATTR_INDEX_ROOT)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0                    // 驻留
        rec[off + 9] = nameLen.toByte()
        putU16(rec, off + 10, nameOff)
        putU16(rec, off + 12, attrId)
        putU32(rec, off + 0x10, contentLen.toLong())   // value length
        putU16(rec, off + 0x14, valOff)                 // value offset
        val name = "\$I30"
        for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        val c = off + valOff   // 内容起点
        // INDEX_ROOT 头
        putU32(rec, c + 0x00, 0x30L)    // indexed attr type = $FILE_NAME
        putU32(rec, c + 0x04, 0x01L)    // collation = FILENAME
        putU32(rec, c + 0x08, boot.indexRecordSize.toLong())
        // H4：clusters_per_index_block 单字节编码（与 boot[0x44]、formatter 侧一致），后 3 字节 padding=0。
        putU32(rec, c + 0x0C, (NtfsFormatter.indexBufferCode(clusterSize) and 0xFF).toLong())
        // INDEX_HEADER（内容偏移 0x10）
        putU32(rec, c + 0x10, 0x10L)    // entriesOffset（相对 INDEX_HEADER）
        // index_length = INDEX_HEADER(0x10) + 末项(0x18) = 0x28（从 INDEX_HEADER 起算的已用字节）。
        //   原写 0x18（漏 header 0x10）→ chkdsk 报索引长度不符。修为 0x28。
        putU32(rec, c + 0x14, 0x28L)
        putU32(rec, c + 0x18, (contentLen - 0x10).toLong())  // allocatedSize（同上，INDEX_HEADER 起算）
        putU32(rec, c + 0x1C, 0x01L)    // flags = 大索引
        // 末项（内容偏移 0x20）：LAST | HAS_SUBNODE → VCN 0
        putU64(rec, c + 0x20, 0L)       // mftRef
        putU16(rec, c + 0x28, 0x18)     // entrySize
        putU16(rec, c + 0x2A, 0)        // contentSize
        putU16(rec, c + 0x2C, 0x03)     // flags = LAST | HAS_SUBNODE
        putU16(rec, c + 0x2E, 0)        // padding
        putU64(rec, c + 0x30, 0L)       // subnode VCN = 0
        return off + total
    }

    /** 写 $INDEX_ALLOCATION 属性（非驻留，单 run→[lcn]），返回下一偏移；越界 -1。 */
    private fun writeIndexAllocationAttr(rec: ByteArray, off: Int, lcn: Long, clusters: Long, attrId: Int): Int {
        val runBytes = encodeSingleRun(lcn, clusters)
        val nameLen = 4
        val nameOff = 0x40
        val runOff = nameOff + nameLen * 2   // 0x48
        val total = align8(runOff + runBytes.size)
        if (off + total > recordSize) return -1
        putU32(rec, off, ATTR_INDEX_ALLOCATION)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 1                    // 非驻留
        rec[off + 9] = nameLen.toByte()
        putU16(rec, off + 10, nameOff)
        putU16(rec, off + 12, attrId)
        putU64(rec, off + 0x10, 0L)         // start VCN
        putU64(rec, off + 0x18, (clusters - 1))   // end VCN
        putU16(rec, off + 0x20, runOff)     // runs 偏移
        rec[off + 0x22] = 0                 // compression unit
        putU64(rec, off + 0x28, (clusters * clusterSize).toLong())   // allocated size
        putU64(rec, off + 0x30, (clusters * clusterSize).toLong())   // real size
        putU64(rec, off + 0x38, (clusters * clusterSize).toLong())   // initialized size
        val name = "\$I30"
        for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        System.arraycopy(runBytes, 0, rec, off + runOff, runBytes.size)
        return off + total
    }

    /** 写 $BITMAP 属性（驻留，INDX 记录位图），返回下一偏移；越界 -1。 */
    private fun writeIndexBitmapAttr(rec: ByteArray, off: Int, attrId: Int): Int {
        val bmp = byteArrayOf(0x01)         // VCN 0 已用（W5）
        val nameLen = 4
        val nameOff = 0x18
        val valOff = nameOff + nameLen * 2   // 0x20
        val total = align8(valOff + bmp.size)
        if (off + total > recordSize) return -1
        putU32(rec, off, 0xB0L)             // $BITMAP
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0                    // 驻留
        rec[off + 9] = nameLen.toByte()
        putU16(rec, off + 10, nameOff)
        putU16(rec, off + 12, attrId)
        putU32(rec, off + 0x10, bmp.size.toLong())   // value length
        putU16(rec, off + 0x14, valOff)               // value offset
        val name = "\$I30"
        for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        System.arraycopy(bmp, 0, rec, off + valOff, bmp.size)
        return off + total
    }
    /**
     * 从目录 [dirRef] 删除名为 [name] 的索引项（含其 DOS 短名孪生项，按同一 mftRef 一并删）。
     * 走整树重建：收集全树 → 剔除目标 mftRef 的所有项 → 重建。找不到 / >2 层 → false。
     */
    private fun removeIndexEntry(dirRef: Long, name: String): Boolean {
        val rec = readMftRecord(dirRef) ?: return false
        val attrs = parseAttrs(rec)
        val root = findAttr(attrs, ATTR_INDEX_ROOT, "\$I30") ?: return false
        if (root.nonResident) return false
        val all = collectAllLeafEntries(rec, attrs) ?: return false
        // 定位目标项：名匹配（跳过纯 DOS 名，与列目录一致）。
        val target = all.firstOrNull { e ->
            val ns = if (u16(e, 10) >= 0x42) (e[0x10 + 0x41].toInt() and 0xFF) else -1
            ns != NS_DOS && entryFileName(e) == name
        } ?: return false
        val targetRef = entryMftRef(target)
        // 剔除同一 mftRef 的所有项（长名 + DOS 短名孪生），避免留孤儿项。
        val kept = all.filter { entryMftRef(it) != targetRef }
        if (kept.size == all.size) return false   // 没删掉任何项 = 异常
        return rebuildDirIndex(dirRef, kept)
    }

    // ================= B+树整树重建（放开 W4 保守拒绝：单叶满分裂 / 多叶插删）=================
    //
    // 策略：insert/delete 统一为「collectAllLeafEntries 全树 → 增/删一项 → rebuildDirIndex 从排序表重建」。
    // 一条路径，一处对处处对。支持 2 层 B+树（root 指针节点 + N 个 INDX 叶子）；3 层（需 root 放不下
    // 全部分隔符）保守拒绝。仅 indexRecordSize>=clusterSize（4096 索引 + 簇<=4096，绝大多数容器）走多叶；
    // 超大簇(idxRecSize<clusterSize)的多叶 VCN 编码复杂，保守拒绝。
    // NTFS 索引是 B-树：分隔符键项提升到 root（带 HAS_SUBNODE+子节点 VCN），不在叶子重复；
    //   读侧遍历 root 键项 + 全叶子项去重，故收集必须含 root 键项。

    /** 把任意索引项（可能带子节点 VCN）剥离成纯叶子项：保留 mftRef+content，清 flags，重算 entryLen。 */
    private fun stripToLeafEntry(entry: ByteArray): ByteArray {
        val contentLen = u16(entry, 10)
        val bodyLen = 0x10 + contentLen
        val entryLen = align8(bodyLen)
        val out = ByteArray(entryLen)
        System.arraycopy(entry, 0, out, 0, minOf(bodyLen, entry.size))
        putU16(out, 8, entryLen)
        putU16(out, 12, 0)   // flags=0：叶子项（无子节点、非末项）
        return out
    }

    /** 把叶子项转成 root 键项（带 HAS_SUBNODE + 尾部 8 字节子节点 VCN）。 */
    private fun buildSubnodeEntry(leafEntry: ByteArray, subnodeVcn: Long): ByteArray {
        val contentLen = u16(leafEntry, 10)
        val bodyLen = 0x10 + contentLen + 8
        val entryLen = align8(bodyLen)
        val out = ByteArray(entryLen)
        System.arraycopy(leafEntry, 0, out, 0, 0x10 + contentLen)
        putU16(out, 8, entryLen)
        putU16(out, 12, INDEX_ENTRY_HAS_SUBNODE)
        putU64(out, 0x10 + contentLen, subnodeVcn)
        return out
    }

    /**
     * 收集目录 [rec] 整棵索引树的全部叶子形式项（含 root 分隔符键项 + 所有 INDX 叶子项）。
     * 检测 >2 层（叶子项自带 HAS_SUBNODE）→ 返回 null 保守拒绝。
     */
    private fun collectAllLeafEntries(rec: ByteArray, attrs: List<Attr>): List<ByteArray>? {
        val out = ArrayList<ByteArray>()
        // root 键项（多叶树里带 HAS_SUBNODE 的分隔符也在此，剥离即可）。
        val rootAttrOff = attrOffsetOf(rec, ATTR_INDEX_ROOT, "\$I30") ?: return null
        val rootContentOff = rootAttrOff + u16(rec, rootAttrOff + 0x14)
        val rNodeHdr = rootContentOff + 0x10
        val rEntriesRel = u32(rec, rNodeHdr + 0x00).toInt()
        val rUsed = u32(rec, rNodeHdr + 0x04).toInt()
        var p = rNodeHdr + rEntriesRel
        val rEnd = rNodeHdr + rUsed
        while (p + 0x10 <= rEnd && p + 0x10 <= rec.size) {
            val flags = u16(rec, p + 12)
            val elen = u16(rec, p + 8)
            if (elen < 0x10) break
            if (flags and INDEX_ENTRY_LAST != 0) break
            out.add(stripToLeafEntry(rec.copyOfRange(p, p + elen)))
            p += elen
        }
        // 所有 INDX 叶子。
        val alloc = findAttr(attrs, ATTR_INDEX_ALLOCATION, "\$I30")
        if (alloc != null && alloc.nonResident) {
            val runs = decodeRuns(alloc.recordBuf, alloc.runsOffset)
            val idxSize = boot.indexRecordSize
            var pos = 0L
            while (pos + idxSize <= alloc.realSize) {
                val indx = readFromRuns(runs, pos, idxSize)
                pos += idxSize
                if (indx == null || indx.size < 4 || indx[0] != 'I'.code.toByte()) continue
                applyUsaFixup(indx)
                val nh = 0x18
                val er = u32(indx, nh + 0x00).toInt()
                val us = u32(indx, nh + 0x04).toInt()
                var q = nh + er
                val qEnd = nh + us
                while (q + 0x10 <= qEnd && q + 0x10 <= indx.size) {
                    val f = u16(indx, q + 12)
                    val el = u16(indx, q + 8)
                    if (el < 0x10) break
                    if (f and INDEX_ENTRY_LAST != 0) break
                    if (f and INDEX_ENTRY_HAS_SUBNODE != 0) return null   // 叶子带子节点 = >2 层，拒绝
                    out.add(stripToLeafEntry(indx.copyOfRange(q, q + el)))
                    q += el
                }
            }
        }
        return out
    }

    /** 每个 INDX 记录占的簇数（idxRecSize>=clusterSize 时；否则调用方已拒绝多叶）。 */
    private fun clustersPerIndexRecord(): Long =
        ((boot.indexRecordSize + clusterSize - 1) / clusterSize).toLong()

    /** INDX 叶子可容纳项的字节上限（idxRecSize - INDX头0x18 - INDEX_HEADER0x10 - USA - END0x10，取对齐后的保守值）。 */
    private fun leafEntryCapacity(): Int {
        val idxRecSize = boot.indexRecordSize
        val sectorCount = idxRecSize / boot.bytesPerSector
        val usaBytes = (sectorCount + 1) * 2
        val entriesStart = align8(0x28 + usaBytes)   // 与 buildIndxLeafRecord 一致（USA 在 0x28）
        return idxRecSize - entriesStart - 0x10       // 减 END 叶末项
    }

    /**
     * 从排序好的叶子项 [sorted] 重建目录 [dirRef] 整棵索引。
     * ① 全驻留（所有项+END 塞进 MFT 记录的 $INDEX_ROOT）→ 小目录 / 删到变小的收缩。
     * ② 2 层（分区成 N 个 INDX 叶子 + root 指针节点带分隔符）。
     * ③ root 放不下全部分隔符 = 需 3 层 → false 保守拒绝。
     * 事务序：新簇先分配、新记录+叶子先写，全成功后才释放旧 INDEX_ALLOCATION 簇（先建后拆）。
     */
    private fun rebuildDirIndex(dirRef: Long, sorted: List<ByteArray>): Boolean {
        val origRec = readMftRecord(dirRef) ?: return false
        val origAttrs = parseAttrs(origRec)

        // ① 全驻留尝试。
        val (base, baseOff) = copyBaseDirRecord(origRec) ?: return false
        val rootContent = buildResidentRootContent(sorted)
        run {
            val rec = base.copyOf()
            val rootId = origIndexRootId(origRec)
            var off = writeIndexRootAttrWith(rec, baseOff, rootId, rootContent)
            if (off >= 0 && off + 8 <= recordSize) {
                putU32(rec, off, ATTR_END)
                putU32(rec, 0x18, (off + 8).toLong())
                putU32(rec, 0x1C, recordSize.toLong())
                // next-attr-id 保守取原值与已用 id+1 的较大者。
                putU16(rec, 0x28, maxOf(u16(origRec, 0x28), rootId + 1) and 0xFFFF)
                if (writeMftRecord(dirRef, rec)) { freeOldIndexAlloc(origAttrs); return true }
                return false
            }
            // 放不下 → 落 2 层。
        }

        // ② 2 层：仅 idxRecSize>=clusterSize 支持（超大簇多叶 VCN 编码复杂，拒绝）。
        if (boot.indexRecordSize < clusterSize) return false
        val cap = leafEntryCapacity()
        // 单项若超过一个叶子容量（名极长）→ 无法放 → 拒绝。
        if (sorted.any { it.size > cap }) return false

        // 贪心分区：填满一叶就把下一项提升为分隔符，起新叶。
        val leaves = ArrayList<List<ByteArray>>()
        val separators = ArrayList<ByteArray>()
        var cur = ArrayList<ByteArray>()
        var curBytes = 0
        for (e in sorted) {
            if (curBytes + e.size > cap) {
                leaves.add(cur); separators.add(e)
                cur = ArrayList(); curBytes = 0
            } else { cur.add(e); curBytes += e.size }
        }
        leaves.add(cur)
        val numLeaves = leaves.size

        // root 大索引内容（分隔符各带子节点 VCN + LAST→末叶 VCN）；放不下 = 需 3 层。
        val cpr = clustersPerIndexRecord()
        val largeRoot = buildLargeRootContent(separators, numLeaves, cpr) ?: return false

        // 组装目录 FILE 记录：非索引属性 + 大 $INDEX_ROOT + $INDEX_ALLOCATION + $BITMAP + END。
        val totalClusters = numLeaves * cpr
        val lcn = allocContiguousClusters(totalClusters)
        if (lcn < 0) return false
        val newRec = base.copyOf()
        val rootId = origIndexRootId(origRec)
        val allocId = maxOf(u16(origRec, 0x28), rootId + 1)
        val bmpId = allocId + 1
        var off = writeIndexRootAttrWith(newRec, baseOff, rootId, largeRoot)
        if (off < 0) { freeClusters(lcn, totalClusters); return false }
        off = writeIndexAllocationAttr(newRec, off, lcn, totalClusters, allocId)
        if (off < 0) { freeClusters(lcn, totalClusters); return false }
        off = writeIndexBitmapMulti(newRec, off, bmpId, numLeaves)
        if (off < 0) { freeClusters(lcn, totalClusters); return false }
        if (off + 8 > recordSize) { freeClusters(lcn, totalClusters); return false }
        putU32(newRec, off, ATTR_END)
        putU32(newRec, 0x18, (off + 8).toLong())
        putU32(newRec, 0x1C, recordSize.toLong())
        putU16(newRec, 0x28, (bmpId + 1) and 0xFFFF)

        // 写各叶子 INDX（VCN = i*cpr），先打 USA。
        for (i in 0 until numLeaves) {
            val vcn = i.toLong() * cpr
            val indx = buildIndxLeafRecord(leaves[i], vcn) ?: run { freeClusters(lcn, totalClusters); return false }
            stampUsa(indx)
            reader.write((lcn + i.toLong() * cpr) * clusterSize, indx, 0, indx.size)
        }
        if (!writeMftRecord(dirRef, newRec)) { freeClusters(lcn, totalClusters); return false }
        freeOldIndexAlloc(origAttrs)   // 先建后拆：新记录写成功才释放旧簇
        return true
    }

    /** 原 $INDEX_ROOT 的属性 id（复用，无则 2）。 */
    private fun origIndexRootId(origRec: ByteArray): Int {
        val o = attrOffsetOf(origRec, ATTR_INDEX_ROOT, "\$I30") ?: return 2
        return u16(origRec, o + 0x0C)
    }

    /**
     * 建 2 层 root 的 $INDEX_ROOT 内容（flags=1 大索引）：分隔符键项（各 HAS_SUBNODE+子节点 VCN=i*cpr）
     * + LAST 项（HAS_SUBNODE+LAST，子节点 VCN=末叶）。放不进 resident root 上限 → null（需 3 层）。
     */
    private fun buildLargeRootContent(separators: List<ByteArray>, numLeaves: Int, cpr: Long): ByteArray? {
        // 分隔符 i 的子节点 = 叶 i（含 < 分隔符 i 的项），VCN = i*cpr。LAST 子节点 = 叶 numLeaves-1。
        val subEntries = ArrayList<ByteArray>(separators.size)
        for (i in separators.indices) subEntries.add(buildSubnodeEntry(separators[i], i.toLong() * cpr))
        var body = 0x20   // INDEX_ROOT头 + INDEX_HEADER
        for (e in subEntries) body += e.size
        body += 0x18       // LAST 带子节点项
        // resident root 上限：MFT 记录减去其它属性余量很难精确，这里用「INDEX_ROOT 内容 <= idxRecSize」+
        //   调用方 writeIndexRootAttrWith 的 recordSize 越界检查兜底。内容过大即返回 null。
        if (0x20 + subEntries.sumOf { it.size } + 0x18 > recordSize - 0x40) return null
        val c = ByteArray(body)
        putU32(c, 0x00, 0x30L); putU32(c, 0x04, 0x01L)
        putU32(c, 0x08, boot.indexRecordSize.toLong())
        putU32(c, 0x0C, (NtfsFormatter.indexBufferCode(clusterSize) and 0xFF).toLong())
        putU32(c, 0x10, 0x10L)                          // entriesOffset
        putU32(c, 0x14, (body - 0x10).toLong())         // index_length（含头+分隔符+LAST）
        putU32(c, 0x18, (body - 0x10).toLong())         // allocated_size
        putU32(c, 0x1C, 0x01L)                          // flags = 大索引
        var p = 0x20
        for (e in subEntries) { System.arraycopy(e, 0, c, p, e.size); p += e.size }
        // LAST 带子节点项（0x18）→ 末叶 VCN。
        putU64(c, p + 0x00, 0L)                         // mftRef=0
        putU16(c, p + 0x08, 0x18)                       // entrySize
        putU16(c, p + 0x0A, 0)                          // contentSize
        putU16(c, p + 0x0C, (INDEX_ENTRY_LAST or INDEX_ENTRY_HAS_SUBNODE))
        putU16(c, p + 0x0E, 0)
        putU64(c, p + 0x10, (numLeaves - 1).toLong() * cpr)   // 末叶子节点 VCN
        return c
    }

    /** 写 $BITMAP 属性（驻留，前 [usedRecords] 位=1，其余 0，按 8 字节对齐）。返回下一偏移；越界 -1。 */
    private fun writeIndexBitmapMulti(rec: ByteArray, off: Int, attrId: Int, usedRecords: Int): Int {
        val byteLen = maxOf(8, (usedRecords + 7) / 8)   // 至少 8 字节（NTFS $BITMAP 惯例 8 对齐）
        val bmp = ByteArray(byteLen)
        for (i in 0 until usedRecords) bmp[i / 8] = (bmp[i / 8].toInt() or (1 shl (i % 8))).toByte()
        val nameLen = 4; val nameOff = 0x18; val valOff = nameOff + nameLen * 2
        val total = align8(valOff + bmp.size)
        if (off + total > recordSize) return -1
        putU32(rec, off, 0xB0L); putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0; rec[off + 9] = nameLen.toByte()
        putU16(rec, off + 10, nameOff); putU16(rec, off + 12, attrId)
        putU32(rec, off + 0x10, bmp.size.toLong()); putU16(rec, off + 0x14, valOff)
        val name = "\$I30"; for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        System.arraycopy(bmp, 0, rec, off + valOff, bmp.size)
        return off + total
    }

    // ---- 内存自测（去险：NTFS 是死代码没法真机跑，自测在编译期揪层布局 bug）----

    /** 解析一段索引项（从 [start] 起，遇 LAST 停），返回各项文件名。用于自测回解。 */
    private fun parseEntryNames(buf: ByteArray, start: Int, end: Int): List<String> {
        val out = ArrayList<String>()
        var p = start
        while (p + 0x10 <= end && p + 0x10 <= buf.size) {
            val flags = u16(buf, p + 12)
            val elen = u16(buf, p + 8)
            if (elen < 0x10) break
            if (flags and INDEX_ENTRY_LAST != 0) break
            out.add(entryFileName(buf.copyOfRange(p, p + elen)))
            p += elen
        }
        return out
    }

    /**
     * 索引 B+树内存自测：合成 N 项跑重建各布局，读侧回解，断言集合+顺序+签名+尺寸。
     * 全程内存、零磁盘、无副作用。返回逐项结果串。这是 NTFS 死代码阶段唯一自动裁判。
     */
    internal fun ntfsIndexSelfTest(): String {
        val sb = StringBuilder()
        fun mkEntry(idx: Int): ByteArray {
            val name = "file%05d.dat".format(idx)   // 定长名，可预测容量
            val fn = buildFileNameForIndex(0L, MFT_ROOT_DIR, name, 1234L, 4096L, isDir = false)
            return stripToLeafEntry(buildIndexEntry(fn, 100L + idx, hasSubnode = false, isLast = false))
        }

        // —— 用例 1：全驻留（小目录）——
        run {
            val n = 6
            val entries = (1..n).map { mkEntry(it) }
                .sortedWith(Comparator { a, b -> entryFileName(a).compareTo(entryFileName(b), ignoreCase = true) })
            val content = buildResidentRootContent(entries)
            val idxLen = u32(content, 0x14).toInt()
            val names = parseEntryNames(content, 0x20, 0x20 + (idxLen - 0x10))
            val expect = entries.map { entryFileName(it) }
            val ok = names == expect && idxLen == content.size - 0x10
            sb.append("[驻留 n=$n] ").append(if (ok) "PASS" else "FAIL got=${names.size} idxLen=$idxLen size=${content.size}").append("\n")
        }

        // —— 用例 2：2 层 B+树（大目录，强制分裂）——
        run {
            if (boot.indexRecordSize < clusterSize) { sb.append("[2层] SKIP(超大簇)\n"); return@run }
            val cap = leafEntryCapacity()
            val perEntry = mkEntry(1).size
            val n = (cap / perEntry) * 3 + 5   // 约填 3 个叶子有余，保证多叶
            val entries = (1..n).map { mkEntry(it) }
                .sortedWith(Comparator { a, b -> entryFileName(a).compareTo(entryFileName(b), ignoreCase = true) })
            // 复刻 rebuildDirIndex 的分区。
            val leaves = ArrayList<List<ByteArray>>(); val seps = ArrayList<ByteArray>()
            var cur = ArrayList<ByteArray>(); var curBytes = 0
            for (e in entries) {
                if (curBytes + e.size > cap) { leaves.add(cur); seps.add(e); cur = ArrayList(); curBytes = 0 }
                else { cur.add(e); curBytes += e.size }
            }
            leaves.add(cur)
            val numLeaves = leaves.size
            val cpr = clustersPerIndexRecord()

            // 回解：全局顺序 = leaf0 ++ [sep0] ++ leaf1 ++ [sep1] ++ ... ++ leafK。
            val rebuilt = ArrayList<String>()
            var badLeaf = -1
            for (i in 0 until numLeaves) {
                val indx = buildIndxLeafRecord(leaves[i], i.toLong() * cpr)
                if (indx == null || indx[0] != 'I'.code.toByte() || indx[3] != 'X'.code.toByte()) { badLeaf = i; break }
                val er = u32(indx, 0x18).toInt(); val us = u32(indx, 0x18 + 0x04).toInt()
                rebuilt.addAll(parseEntryNames(indx, 0x18 + er, 0x18 + us))
                if (i < seps.size) rebuilt.add(entryFileName(seps[i]))
            }
            val largeRoot = buildLargeRootContent(seps, numLeaves, cpr)
            val rootNames = if (largeRoot != null) parseEntryNames(largeRoot, 0x20, 0x20 + (u32(largeRoot, 0x14).toInt() - 0x10)) else emptyList()
            val expect = entries.map { entryFileName(it) }
            val orderOk = rebuilt == expect
            val rootOk = largeRoot != null && rootNames == seps.map { entryFileName(it) } && (u32(largeRoot, 0x1C).toInt() and 1) == 1
            val countOk = numLeaves == seps.size + 1
            val ok = badLeaf < 0 && orderOk && rootOk && countOk
            sb.append("[2层 n=$n 叶=$numLeaves 分隔=${seps.size} cap=$cap] ")
                .append(if (ok) "PASS" else "FAIL badLeaf=$badLeaf order=$orderOk root=$rootOk cnt=$countOk").append("\n")
        }

        // —— 用例 3：驻留↔收缩边界（删到能塞回驻留）——
        run {
            val entries = (1..3).map { mkEntry(it) }
                .sortedWith(Comparator { a, b -> entryFileName(a).compareTo(entryFileName(b), ignoreCase = true) })
            val content = buildResidentRootContent(entries)
            val flags = u32(content, 0x1C).toInt()
            val ok = flags == 0   // 小索引 flags=0（无 INDEX_ALLOCATION）
            sb.append("[驻留 flags] ").append(if (ok) "PASS" else "FAIL flags=$flags").append("\n")
        }
        return sb.toString()
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
     * 复制 [origRec] 的 FILE 头 + 所有非索引属性（跳过 $INDEX_ROOT/$INDEX_ALLOCATION/$BITMAP 带 $I30 名）
     * 到新记录，返回 (新记录, 下一属性偏移)。失败返 null。用于重建目录索引前的骨架。
     */
    private fun copyBaseDirRecord(origRec: ByteArray): Pair<ByteArray, Int>? {
        val rec = ByteArray(recordSize)
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, u16(origRec, 4)); putU16(rec, 6, u16(origRec, 6))     // USA off/count
        putU64(rec, 8, u64(origRec, 8))                                       // LSN
        putU16(rec, 16, u16(origRec, 16)); putU16(rec, 18, u16(origRec, 18))  // 序列号 / 硬链接
        val firstAttrOff = u16(origRec, 20)
        putU16(rec, 20, firstAttrOff)
        putU16(rec, 22, u16(origRec, 22))                                     // 标志（目录=0x02）
        putU32(rec, 0x2C, u32(origRec, 0x2C))                                 // 本记录号
        var off = firstAttrOff
        var attrOff = firstAttrOff
        val origUsed = u32(origRec, 0x18).toInt()
        while (attrOff + 8 <= origUsed && attrOff + 8 <= origRec.size) {
            val type = u32(origRec, attrOff)
            if (type == ATTR_END) break
            val totalLen = u32(origRec, attrOff + 4).toInt()
            if (totalLen <= 0 || attrOff + totalLen > origUsed) break
            val nameLen = origRec[attrOff + 9].toInt() and 0xFF
            val nameOff = u16(origRec, attrOff + 10)
            val an = if (nameLen > 0) {
                val sb = StringBuilder(nameLen)
                for (k in 0 until nameLen) sb.append(u16(origRec, attrOff + nameOff + k * 2).toChar())
                sb.toString()
            } else ""
            val isIndexAttr = (type == ATTR_INDEX_ROOT || type == ATTR_INDEX_ALLOCATION || type == 0xB0L) && an == "\$I30"
            if (!isIndexAttr) {
                if (off + totalLen > recordSize) return null
                System.arraycopy(origRec, attrOff, rec, off, totalLen)
                off += totalLen
            }
            attrOff += totalLen
        }
        return Pair(rec, off)
    }

    /** 释放 [attrs] 里 $INDEX_ALLOCATION($I30) 的全部簇（重建前回收旧空间）。 */
    private fun freeOldIndexAlloc(attrs: List<Attr>) {
        val alloc = findAttr(attrs, ATTR_INDEX_ALLOCATION, "\$I30") ?: return
        if (!alloc.nonResident) return
        val runs = decodeRuns(alloc.recordBuf, alloc.runsOffset)
        for (run in runs) if (!run.sparse) freeClusters(run.lcn, run.length)
    }

    /**
     * 建全驻留 $INDEX_ROOT 内容（flags=0 小索引）：INDEX_ROOT头(0x10)+INDEX_HEADER(0x10)+全部项+END(0x10 叶末项)。
     * 内容字节，供 writeIndexRootAttr 包成属性。调用方保证已排序。
     */
    private fun buildResidentRootContent(entries: List<ByteArray>): ByteArray {
        var body = 0x20   // INDEX_ROOT头 + INDEX_HEADER
        for (e in entries) body += e.size
        body += 0x10       // END 叶末项
        val c = ByteArray(body)
        putU32(c, 0x00, 0x30L)                          // indexed attr = $FILE_NAME
        putU32(c, 0x04, 0x01L)                          // collation = FILENAME
        putU32(c, 0x08, boot.indexRecordSize.toLong())
        putU32(c, 0x0C, (NtfsFormatter.indexBufferCode(clusterSize) and 0xFF).toLong())
        putU32(c, 0x10, 0x10L)                          // entriesOffset（相对 INDEX_HEADER）
        putU32(c, 0x14, (body - 0x10).toLong())         // index_length = 从 INDEX_HEADER 起的已用（含头+项+END）
        putU32(c, 0x18, (body - 0x10).toLong())         // allocated_size（驻留=已用）
        putU32(c, 0x1C, 0x00L)                          // flags = 0 小索引
        var p = 0x20
        for (e in entries) { System.arraycopy(e, 0, c, p, e.size); p += e.size }
        // END 叶末项（0x10，无子节点）
        putU16(c, p + 8, 0x10); putU16(c, p + 12, INDEX_ENTRY_LAST)
        return c
    }

    /** 把 $INDEX_ROOT 内容 [content] 写成属性（驻留，名 $I30），返回下一偏移；越界 -1。 */
    private fun writeIndexRootAttrWith(rec: ByteArray, off: Int, attrId: Int, content: ByteArray): Int {
        val nameLen = 4; val nameOff = 0x18; val valOff = nameOff + nameLen * 2   // 0x20
        val total = align8(valOff + content.size)
        if (off + total > recordSize) return -1
        putU32(rec, off, ATTR_INDEX_ROOT); putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0; rec[off + 9] = nameLen.toByte()
        putU16(rec, off + 10, nameOff); putU16(rec, off + 12, attrId)
        putU32(rec, off + 0x10, content.size.toLong()); putU16(rec, off + 0x14, valOff)
        val name = "\$I30"; for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        System.arraycopy(content, 0, rec, off + valOff, content.size)
        return off + total
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



    // ================= W15 NTFS 目录操作（rename/mkdir/move/rmdir）=================
    //
    // 依赖 W4 的 insertIndexEntry（三路径）+ 现有 removeIndexEntry/ntfsDeleteFile。
    // 保守原则同 W4：需 B+树分裂而 W4 未覆盖的场景一律返回 false 不动盘。
    // 句柄语义：dirFirstCluster 实为 MFT 记录号（listDir 返回 firstCluster = MFT ref）；
    //   根目录（< 16）映射到 MFT_ROOT_DIR(5)。

    override fun rename(dirFirstCluster: Long, oldName: String, newName: String): Boolean =
        ntfsRename(normDir(dirFirstCluster), oldName, newName)

    override fun mkdir(dirFirstCluster: Long, name: String): Long =
        ntfsMkDir(normDir(dirFirstCluster), name)

    override fun rmdir(dirFirstCluster: Long, name: String, recursive: Boolean): Boolean =
        ntfsRmDir(normDir(dirFirstCluster), name, recursive)

    override fun move(srcDirFirstCluster: Long, name: String, dstDirFirstCluster: Long): Boolean =
        ntfsMove(normDir(srcDirFirstCluster), name, normDir(dstDirFirstCluster))

    /** UI 句柄 < 16 视为根目录（与 listDir/writeFile 同一规则）。 */
    private fun normDir(ref: Long): Long = if (ref < 16) MFT_ROOT_DIR else ref

    /**
     * 建子目录 [name] 于 [dirRef]。成功返回新目录 MFT 记录号（>0）；失败返回 0。
     * 流程：allocMftRecord → buildDirRecord（含 $INDEX_ROOT 空树）→ writeMftRecord
     *   → insertIndexEntry（复用 W4）。任何步骤失败回滚已分配的 MFT 记录。
     */
    private fun ntfsMkDir(dirRef: Long, name: String): Long {
        if (name.isEmpty() || name.length > 255) return 0L
        if (listDirEntries(dirRef).any { it.name.equals(name, ignoreCase = false) }) return 0L
        val newRef = allocMftRecord()
        if (newRef < 0) return 0L
        val rec = buildDirRecord(newRef, dirRef, name)
        if (rec == null) { freeMftRecord(newRef); return 0L }
        if (!writeMftRecord(newRef, rec)) { freeMftRecord(newRef); return 0L }
        val fnContent = buildFileNameForIndex(0L, dirRef, name, 0L, 0L, isDir = true)
        if (!insertIndexEntry(dirRef, fnContent, newRef)) {
            val bad = rec.copyOf()
            putU16(bad, 0x16, u16(rec, 0x16) and FLAG_IN_USE.inv())
            putU16(bad, 16, (u16(rec, 16) + 1) and 0xFFFF)
            writeMftRecord(newRef, bad)
            freeMftRecord(newRef)
            return 0L
        }
        return newRef
    }

    /**
     * 组建目录 FILE 记录：FILE 头（FLAG_IN_USE|FLAG_DIRECTORY）+ $STANDARD_INFORMATION
     *   + $FILE_NAME（isDir）+ $INDEX_ROOT 空树（$I30，末项 LAST）+ $END。
     * 与 [buildFileRecord] 区别：无 $DATA，多 $INDEX_ROOT；记录头标志含 DIRECTORY。
     */
    private fun buildDirRecord(recordNo: Long, parentRef: Long, name: String): ByteArray? {
        val rec = ByteArray(recordSize)
        val sectorCount = recordSize / bootSectorSize()
        val usaCount = sectorCount + 1
        val usaOff = 0x30
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, usaOff)
        putU16(rec, 6, usaCount)
        putU64(rec, 8, 0L)
        putU16(rec, 16, 1)
        putU16(rec, 18, 1)
        val firstAttrOff = align8(usaOff + usaCount * 2)
        putU16(rec, 20, firstAttrOff)
        putU16(rec, 22, FLAG_IN_USE or FLAG_DIRECTORY)
        putU16(rec, 0x28, 7)
        putU16(rec, 0x2A, 0)
        putU32(rec, 0x2C, recordNo)
        var off = firstAttrOff
        off = writeStdInfo(rec, off)
        off = writeFileNameAttr(rec, off, parentRef, name, 0L, 0L)
        if (off < 0) return null
        off = writeEmptyIndexRootAttr(rec, off, 2)
        if (off < 0) return null
        if (off + 8 > recordSize) return null
        putU32(rec, off, ATTR_END)
        putU32(rec, 0x18, (off + 8).toLong())
        putU32(rec, 0x1C, recordSize.toLong())
        return rec
    }

    /**
     * 写空 $INDEX_ROOT 属性（$I30，驻留，小索引）：INDEX_ROOT头 + INDEX_HEADER
     *   + 末项（LAST，无内容，无子节点，0x10 字节）。返回下一偏移；越界 -1。
     * 与 [writeLargeIndexRootAttr] 区别：flags=0（小索引），末项无 HAS_SUBNODE。
     */
    private fun writeEmptyIndexRootAttr(rec: ByteArray, off: Int, attrId: Int): Int {
        val contentLen = 0x30
        val nameLen = 4
        val nameOff = 0x18
        val valOff = nameOff + nameLen * 2
        val total = align8(valOff + contentLen)
        if (off + total > recordSize) return -1
        putU32(rec, off, ATTR_INDEX_ROOT)
        putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0
        rec[off + 9] = nameLen.toByte()
        putU16(rec, off + 10, nameOff)
        putU16(rec, off + 12, attrId)
        putU32(rec, off + 0x10, contentLen.toLong())
        putU16(rec, off + 0x14, valOff)
        val name = "\$I30"
        for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        val c = off + valOff
        putU32(rec, c + 0x00, 0x30L)
        putU32(rec, c + 0x04, 0x01L)
        putU32(rec, c + 0x08, boot.indexRecordSize.toLong())
        // H4：clusters_per_index_block 单字节编码（与 boot[0x44] 一致），后 3 字节 padding=0。
        putU32(rec, c + 0x0C, (NtfsFormatter.indexBufferCode(clusterSize) and 0xFF).toLong())
        putU32(rec, c + 0x10, 0x10L)
        putU32(rec, c + 0x14, 0x20L)
        putU32(rec, c + 0x18, (contentLen - 0x10).toLong())
        putU32(rec, c + 0x1C, 0x00L)
        putU64(rec, c + 0x20, 0L)
        putU16(rec, c + 0x28, 0x10)
        putU16(rec, c + 0x2A, 0)
        putU16(rec, c + 0x2C, INDEX_ENTRY_LAST)
        putU16(rec, c + 0x2E, 0)
        return off + total
    }

    /**
     * 重命名 [dirRef] 下 [oldName] 为 [newName]。
     * 改目标 FILE 记录的 $FILE_NAME 属性（保留 parentRef/时间/size，仅换名）
     *   + 父目录索引项删旧名插新名。保守拒绝：新名已存在 / 名超长 / 记录放不下。
     */
    private fun ntfsRename(dirRef: Long, oldName: String, newName: String): Boolean {
        if (newName.isEmpty() || newName.length > 255) return false
        if (oldName == newName) return true
        val target = listDirEntriesWithRef(dirRef).firstOrNull { it.second == oldName }?.first ?: return false
        if (listDirEntries(dirRef).any { it.name.equals(newName, ignoreCase = false) }) return false
        val rec = readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        val fnAttr = findAttr(attrs, ATTR_FILE_NAME) ?: return false
        val newRec = rewriteFileNameAttr(rec, fnAttr, newName) ?: return false
        if (!writeMftRecord(target, newRec)) return false
        if (!removeIndexEntry(dirRef, oldName)) {
            val rolled = rewriteFileNameAttr(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, oldName)
            if (rolled != null) writeMftRecord(target, rolled)
            return false
        }
        val realSize = readDataRealSize(attrs)
        val allocSize = readDataAllocSize(attrs)
        val isDir = (u16(rec, 0x16) and FLAG_DIRECTORY) != 0
        val fnContent = buildFileNameForIndex(0L, dirRef, newName, realSize, allocSize, isDir)
        if (!insertIndexEntry(dirRef, fnContent, target)) {
            val oldFn = buildFileNameForIndex(0L, dirRef, oldName, realSize, allocSize, isDir)
            insertIndexEntry(dirRef, oldFn, target)
            val rolled = rewriteFileNameAttr(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, oldName)
            if (rolled != null) writeMftRecord(target, rolled)
            return false
        }
        return true
    }

    /**
     * 重写 $FILE_NAME 属性内容为 [newName]（保留 parentRef/4 时间戳/allocSize/realSize/flags/reparse）。
     * 名字长度变化 → 属性总长变化 → 后续属性整体平移 + 记录 used size 更新。放不下返回 null。
     */
    private fun rewriteFileNameAttr(rec: ByteArray, fnAttr: Attr, newName: String): ByteArray? {
        val fnOff = attrOffsetOf(rec, ATTR_FILE_NAME, "") ?: return null
        val hdr = u16(rec, fnOff + 0x14)
        val oldContentLen = u32(rec, fnOff + 0x10).toInt()
        val oldTotal = u32(rec, fnOff + 4).toInt()
        val contentStart = fnOff + hdr
        if (oldContentLen < 0x42) return null
        val preserved = rec.copyOfRange(contentStart, contentStart + 0x40)
        val newContentLen = 0x42 + newName.length * 2
        val newTotal = align8(hdr + newContentLen)
        val delta = newTotal - oldTotal
        val recUsed = u32(rec, 0x18).toInt()
        if (recUsed + delta > recordSize) return null
        val newRec = rec.copyOf()
        val afterOff = fnOff + oldTotal
        val moveLen = recUsed - afterOff
        if (moveLen > 0) {
            if (delta > 0) {
                System.arraycopy(rec, afterOff, newRec, afterOff + delta,
                    moveLen.coerceAtMost(recordSize - (afterOff + delta)))
            } else if (delta < 0) {
                System.arraycopy(rec, afterOff, newRec, afterOff + delta, moveLen)
                for (k in 0 until -delta) {
                    val idx = afterOff + delta + moveLen + k
                    if (idx in 0 until recordSize) newRec[idx] = 0
                }
            }
        }
        putU32(newRec, fnOff + 4, newTotal.toLong())
        putU32(newRec, fnOff + 0x10, newContentLen.toLong())
        System.arraycopy(preserved, 0, newRec, contentStart, 0x40)
        newRec[contentStart + 0x40] = newName.length.toByte()
        newRec[contentStart + 0x41] = 1
        for (k in newName.indices) putU16(newRec, contentStart + 0x42 + k * 2, newName[k].code)
        putU32(newRec, 0x18, (recUsed + delta).toLong())
        return newRec
    }

    /**
     * 同卷内把 [srcDirRef] 下的 [name] 移到 [dstDirRef]。
     * 纯目录项操作 + 改 $FILE_NAME 的 parentRef，不搬数据簇。保守拒绝：目标已存在同名。
     */
    private fun ntfsMove(srcDirRef: Long, name: String, dstDirRef: Long): Boolean {
        if (srcDirRef == dstDirRef) return true
        val target = listDirEntriesWithRef(srcDirRef).firstOrNull { it.second == name }?.first ?: return false
        if (listDirEntries(dstDirRef).any { it.name.equals(name, ignoreCase = false) }) return false
        val rec = readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        val fnAttr = findAttr(attrs, ATTR_FILE_NAME) ?: return false
        val newRec = rewriteFileNameParentRef(rec, fnAttr, dstDirRef) ?: return false
        if (!writeMftRecord(target, newRec)) return false
        if (!removeIndexEntry(srcDirRef, name)) {
            val rolled = rewriteFileNameParentRef(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, srcDirRef)
            if (rolled != null) writeMftRecord(target, rolled)
            return false
        }
        val realSize = readDataRealSize(attrs)
        val allocSize = readDataAllocSize(attrs)
        val isDir = (u16(rec, 0x16) and FLAG_DIRECTORY) != 0
        val fnContent = buildFileNameForIndex(0L, dstDirRef, name, realSize, allocSize, isDir)
        if (!insertIndexEntry(dstDirRef, fnContent, target)) {
            val rolled = rewriteFileNameParentRef(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, srcDirRef)
            if (rolled != null) writeMftRecord(target, rolled)
            val oldFn = buildFileNameForIndex(0L, srcDirRef, name, realSize, allocSize, isDir)
            insertIndexEntry(srcDirRef, oldFn, target)
            return false
        }
        return true
    }

    /** 改 $FILE_NAME 内容偏移 0 的 parentRef（保留高 16 位序列号）。 */
    private fun rewriteFileNameParentRef(rec: ByteArray, fnAttr: Attr, newParent: Long): ByteArray? {
        val newRec = rec.copyOf()
        val contentStart = fnAttr.residentValueOffset
        val orig = u64(newRec, contentStart)
        val seq = orig and (-1L shl 48)
        putU64(newRec, contentStart, newParent and 0x0000FFFFFFFFFFFFL or seq)
        return newRec
    }

    /**
     * 删除 [dirRef] 下的子目录 [name]。recursive=false 仅删空目录；true 递归清空后删。
     * 释放目录 $INDEX_ALLOCATION 的簇 + 标记 FILE 记录未用 + freeMftRecord + 父索引项。
     */
    private fun ntfsRmDir(dirRef: Long, name: String, recursive: Boolean): Boolean {
        val target = listDirEntriesWithRef(dirRef).firstOrNull { it.second == name }?.first ?: return false
        val rec = readMftRecord(target) ?: return false
        if ((u16(rec, 0x16) and FLAG_DIRECTORY) == 0) return false
        val children = listDirEntries(target)
        if (children.isNotEmpty() && !recursive) return false
        if (recursive) {
            for (c in children) {
                if (c.isDirectory) ntfsRmDir(target, c.name, true)
                else ntfsDeleteFile(target, c.name)
            }
            if (listDirEntries(target).isNotEmpty()) return false
        }
        if (!removeIndexEntry(dirRef, name)) return false
        val attrs = parseAttrs(rec)
        val alloc = findAttr(attrs, ATTR_INDEX_ALLOCATION, "\$I30")
        if (alloc != null && alloc.nonResident) {
            val runs = decodeRuns(alloc.recordBuf, alloc.runsOffset)
            for (run in runs) if (!run.sparse) freeClusters(run.lcn, run.length)
        }
        val nr = rec.copyOf()
        putU16(nr, 0x16, u16(rec, 0x16) and FLAG_IN_USE.inv())
        putU16(nr, 16, (u16(rec, 16) + 1) and 0xFFFF)
        writeMftRecord(target, nr)
        freeMftRecord(target)
        return true
    }

    /** 读 $DATA 真实大小（驻留取内容长，非驻留取 realSize；无 $DATA 返回 0）。 */
    private fun readDataRealSize(attrs: List<Attr>): Long {
        val data = findAttr(attrs, ATTR_DATA) ?: return 0L
        return if (data.nonResident) data.realSize else data.residentValueLength.toLong()
    }

    /** 读 $DATA 分配大小（非驻留 = realSize 向上簇对齐；驻留 = 内容长）。 */
    private fun readDataAllocSize(attrs: List<Attr>): Long {
        val data = findAttr(attrs, ATTR_DATA) ?: return 0L
        return if (data.nonResident) {
            val clusters = (data.realSize + clusterSize - 1) / clusterSize
            clusters * clusterSize
        } else data.residentValueLength.toLong()
    }

}
