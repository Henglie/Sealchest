package com.henglie.sealchest.fs

import com.henglie.sealchest.fs.NtfsRecordCodec.Attr
import com.henglie.sealchest.fs.NtfsRecordCodec.DataRun
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_DATA
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_VOLUME_INFO
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.MFT_VOLUME
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.VOLUME_FLAG_DIRTY
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.decodeRuns
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.findAttr
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.parseAttrs
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u16
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u32
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u64

/**
 * NTFS $MFT 管理器：MFT 记录读写、$MFT/$Bitmap/$MFTMirr 定位、MFT 记录位图与簇位图。
 *
 * 从 [NtfsFileSystem] 拆出的 MFT / 位图管理层。独占全部可变状态（7 个 var）：
 * currentLsn / mftDataRuns / mftMirrRuns / clusterBitmapRuns / clusterBitmapResident /
 * mftBitmapRuns / mftBitmapResident。
 *
 * 依赖 [NtfsRecordCodec] 的 USA 修复与工具方法，被 [NtfsIndex] / [NtfsDataOps] 调用。
 */
class NtfsMftManager(
    private val reader: VolumeReader,
    private val boot: NtfsBoot,
    private val codec: NtfsRecordCodec,
) {
    private val bytesPerCluster = boot.bytesPerCluster
    private val mftRecordSize = boot.fileRecordSize

    /** $LogFile LSN 单调递增计数器（本层不写 $LogFile 日志，但 Windows 期望 FILE 记录 LSN 非零且递增）。 */
    private var currentLsn = 0L
    internal fun nextLsn(): Long { currentLsn++; return currentLsn }

    /** $MFT 自身的 data runs（bootstrap 后填），用于定位任意 MFT 记录。 */
    private var mftDataRuns: List<DataRun>? = null

    private var mftMirrRuns: List<DataRun>? = null

    // ---- 底层：按逻辑偏移读、USA 修复 ----

    /** 读 MFT 第 [recordNo] 条记录（已 USA 修复）。越界返回 null。 */
    internal fun readMftRecord(recordNo: Long): ByteArray? {
        // $MFT 自身可能非连续，但第一段（含前若干记录）总在 mftLcn。简化：用 $MFT 的
        // data runs 定位任意记录。先读 $MFT 记录 0 拿它的 runs，再定位目标记录簇。
        val mftData = mftDataRuns ?: return readMftRecordLinear(recordNo)
        val byteOffInMft = recordNo * mftRecordSize
        val buf = readFromRuns(mftData, byteOffInMft, mftRecordSize) ?: return null
        if (!codec.applyUsaFixup(buf)) return null
        if (buf.size < 4 || buf[0] != 'F'.code.toByte()) return null
        return buf
    }

    /** $MFT runs 未就绪时（bootstrap）：假定 MFT 从 mftLcn 起连续，线性定位。 */
    private fun readMftRecordLinear(recordNo: Long): ByteArray? {
        val off = boot.mftByteOffset + recordNo * mftRecordSize
        val buf = reader.read(off, mftRecordSize)
        if (buf.size < 4 || buf[0] != 'F'.code.toByte()) return null
        if (!codec.applyUsaFixup(buf)) return null
        return buf
    }

    /** 从 runs 读 [byteOffset] 起 [length] 字节（跨 run 拼接，稀疏补零）。 */
    internal fun readFromRuns(runs: List<DataRun>, byteOffset: Long, length: Int): ByteArray? {
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

    internal fun bootstrapMft() {
        // 线性读 $MFT 记录 0（记录 0 = $MFT 本身），解出其 $DATA 的 runs。
        val rec0 = readMftRecordLinear(0L) ?: return
        val attrs = parseAttrs(rec0)
        val data = findAttr(attrs, ATTR_DATA) ?: return
        if (data.nonResident) {
            mftDataRuns = decodeRuns(data.recordBuf, data.runsOffset)
        }
    }

    // ---- MFT 记录写 ----

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
        codec.stampUsa(stamped)
        val off = mftRecordLogicalOffset(recordNo) ?: return false
        reader.write(off, stamped, 0, stamped.size)
        if (recordNo < 4) {
            val mirrOff = mftMirrRecordLogicalOffset(recordNo)
            if (mirrOff != null) reader.write(mirrOff, stamped, 0, stamped.size)
        }
        return true
    }

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

    /**
     * 置 $Volume（MFT 记录3）的 $VOLUME_INFORMATION(0x70) 偏移 0x0A flags 字段（u16 低字节）
     * 的 VOLUME_FLAG_DIRTY(0x01) 位。Windows 挂载时据此运行 chkdsk 重建 $LogFile +
     * 校索引一致性——本层不写 $LogFile 日志，靠 dirty 位 + chkdsk 兜底。chkdsk 会清
     * 该位，故每次写操作成功后都须重置。已脏则免写（减少落盘）。
     * 注：flags 在属性内容偏移 0x0A（0x08=MajorVersion/0x09=MinorVersion）。
     */
    internal fun markVolumeDirty() {
        val rec = readMftRecord(MFT_VOLUME) ?: return
        val vi = findAttr(parseAttrs(rec), ATTR_VOLUME_INFO) ?: return
        if (vi.nonResident) return
        val off = vi.residentValueOffset + 0x0A
        if (off >= rec.size) return
        val flags = rec[off].toInt() and 0xFF
        if ((flags and VOLUME_FLAG_DIRTY) != 0) return
        val nr = rec.copyOf()
        nr[off] = (flags or VOLUME_FLAG_DIRTY).toByte()
        writeMftRecord(MFT_VOLUME, nr)
    }

    /**
     * 清 $Volume 的 dirty 位（与 [markVolumeDirty] 对称）。写事务**整体成功落盘后**调，
     * 使卸载后 Windows 挂载时看到 clean 卷、免触发 chkdsk（兑现「别 chkdsk」）。
     *
     * 崩溃安全不变：dirty-first——写事务开头先 markVolumeDirty 且随数据一起 flush，故任何
     * 中途崩溃（clear 之前）卷都停在 dirty=1 → Windows 仍会 chkdsk 补一致性。只有事务完整
     * 落盘后才清位，clear 本身也须再 flush 一次持久化（见 MountManager.withWritableFs）。
     * 已 clean 则免写（减少落盘）。$Volume 是记录 3（<4），writeMftRecord 自动同步 $MFTMirr。
     */
    internal fun clearVolumeDirty() {
        val rec = readMftRecord(MFT_VOLUME) ?: return
        val vi = findAttr(parseAttrs(rec), ATTR_VOLUME_INFO) ?: return
        if (vi.nonResident) return
        val off = vi.residentValueOffset + 0x0A
        if (off >= rec.size) return
        val flags = rec[off].toInt() and 0xFF
        if ((flags and VOLUME_FLAG_DIRTY) == 0) return
        val nr = rec.copyOf()
        nr[off] = (flags and VOLUME_FLAG_DIRTY.inv()).toByte()
        writeMftRecord(MFT_VOLUME, nr)
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
        if (mftBitmapResident != null) {
            // resident 分支：更新内存数组 + 写回 MFT 记录 0 的 $BITMAP 驻留值
            val idx = byteIdx.toInt()
            if (idx < mftBitmapResident!!.size) {
                mftBitmapResident!![idx] = value.toByte()
                val rec0 = readMftRecord(0L) ?: return
                val attrs = parseAttrs(rec0)
                val bmAttr = findAttr(attrs, 0xB0L) ?: return
                if (bmAttr.nonResident) return
                val off = bmAttr.recordBuf.copyOf()
                System.arraycopy(mftBitmapResident!!, 0, off, bmAttr.residentValueOffset,
                    minOf(mftBitmapResident!!.size, bmAttr.residentValueLength))
                writeMftRecord(0L, off)
            }
            return
        }
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
}
