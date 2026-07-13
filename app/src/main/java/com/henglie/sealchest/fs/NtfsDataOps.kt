package com.henglie.sealchest.fs

import com.henglie.sealchest.fs.NtfsRecordCodec.Attr
import com.henglie.sealchest.fs.NtfsRecordCodec.DataRun
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_DATA
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_END
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_FILE_NAME
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_INDEX_ALLOCATION
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_STANDARD_INFO
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_VOLUME_NAME
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.FLAG_DIRECTORY
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.FLAG_IN_USE
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.MFT_ROOT_DIR
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.MFT_VOLUME
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.align8
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.align8Long
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.attrOffsetOf
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.buildFileNameForIndex
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.decodeRuns
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.encodeMultiRun
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.encodeSingleRun
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.findAttr
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.msToNtfsTime
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.parseAttrs
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.putU16
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.putU32
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.putU64
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u16
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u32
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u64

/**
 * NTFS 文件数据操作：文件读/写/删、目录创建/删除/重命名/移动、卷标读取。
 *
 * 从 [NtfsFileSystem] 拆出的高层操作层。无自身状态。调用 [NtfsMftManager] 分配/释放
 * MFT 记录与簇、调用 [NtfsIndex] 维护目录索引、调用 [NtfsRecordCodec] 工具方法。
 *
 * 依赖方向：RecordCodec ← MftManager ← Index ← DataOps ← FileSystem。
 */
class NtfsDataOps(
    private val mftMgr: NtfsMftManager,
    private val index: NtfsIndex,
    private val codec: NtfsRecordCodec,
    private val reader: VolumeReader,
    private val boot: NtfsBoot,
) {
    private val recordSize = boot.fileRecordSize
    private val clusterSize = boot.bytesPerCluster

    // ================= 文件读 =================

    /** 读 MFT 记录 [recordNo] 的 $DATA（无名默认流）。 */
    internal fun readData(recordNo: Long, start: Long, length: Int): ByteArray {
        val rec = mftMgr.readMftRecord(recordNo) ?: return ByteArray(0)
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
        return mftMgr.readFromRuns(runs, start, want) ?: ByteArray(0)
    }

    /** 读 $DATA 真实大小（驻留取内容长，非驻留取 realSize；无 $DATA 返回 0）。 */
    internal fun readDataRealSize(attrs: List<Attr>): Long {
        val data = findAttr(attrs, ATTR_DATA) ?: return 0L
        return if (data.nonResident) data.realSize else data.residentValueLength.toLong()
    }

    /** 读 $DATA 分配大小（非驻留 = realSize 向上簇对齐；驻留 = 内容长）。 */
    internal fun readDataAllocSize(attrs: List<Attr>): Long {
        val data = findAttr(attrs, ATTR_DATA) ?: return 0L
        return if (data.nonResident) {
            val clusters = (data.realSize + clusterSize - 1) / clusterSize
            clusters * clusterSize
        } else data.residentValueLength.toLong()
    }

    // ================= 文件写 =================

    /**
     * 在目录 [dirRef] 下建名为 [name] 的文件，内容 [bytes]。成功 true。
     * 拒绝场景：名已存在 / MFT 满 / 簇不足 / 父目录索引放不下（需 B+树分裂）/ 名过长。
     */
    internal fun ntfsWriteFile(dirRef: Long, name: String, bytes: ByteArray): Boolean {
        if (name.isEmpty() || name.length > 255) return false
        // 名已存在则拒绝（覆写走 overwrite）。
        if (index.listDirEntries(dirRef).any { it.name.equals(name, ignoreCase = false) }) return false

        // 分配新 MFT 记录号。
        val newRef = mftMgr.allocMftRecord()
        if (newRef < 0) return false

        // 决定 $DATA 驻留 / 非驻留：能塞进记录剩余空间就驻留，否则连续分配簇。
        // 记录布局预算：头(56) + $STD_INFO(约72) + $FILE_NAME(约 90+2*len) + $DATA头 + $END(8)。
        val fnContentLen = 0x42 + name.length * 2
        val fnAttrLen = align8(0x18 + fnContentLen)          // 属性头16 + 名字属性头0x08 ... 见构建
        val stdAttrLen = align8(0x18 + 0x48)                 // $STANDARD_INFORMATION 常规 0x48 内容
        val headerAndFixed = 0x38 + 8 /*USA*/ + stdAttrLen + fnAttrLen + 8 /*$END*/
        val residentDataMax = recordSize - headerAndFixed - 0x18 /*$DATA 头*/ - 8
        val resident = bytes.size <= residentDataMax && residentDataMax > 0

        var dataLcn = -1L
        var dataClusters = 0L
        var multiRuns: List<DataRun>? = null   // W6 多段路径
        if (!resident && bytes.isNotEmpty()) {
            dataClusters = (bytes.size + clusterSize - 1).toLong() / clusterSize
            // W6：先试连续（dataLcn），失败走多段（multiRuns）。allocMultipleClusters 空间不足抛异常。
            dataLcn = mftMgr.allocContiguousClusters(dataClusters)
            if (dataLcn < 0) {
                multiRuns = mftMgr.allocMultipleClusters(dataClusters)   // 抛 VolumeFullException 或返回段
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
            if (dataLcn >= 0) mftMgr.freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) mftMgr.freeMultiClusters(multiRuns)
            mftMgr.freeMftRecord(newRef)
            return false
        }

        // 先把索引项插进父目录（可能因放不下而拒绝——此时回滚，不留孤儿记录）。
        val fnEntry = buildFileNameForIndex(newRef, dirRef, name, bytes.size.toLong(),
            allocForIndex(resident, bytes.size.toLong(), dataClusters), false)
        if (!index.insertIndexEntry(dirRef, fnEntry, newRef)) {
            if (dataLcn >= 0) mftMgr.freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) mftMgr.freeMultiClusters(multiRuns)
            mftMgr.freeMftRecord(newRef)
            return false
        }

        // 索引插入成功后再落 FILE 记录（顺序：先索引可回滚，记录落盘即生效）。
        if (!mftMgr.writeMftRecord(newRef, rec)) {
            // 记录写失败：尽力回滚索引 + 资源。
            index.removeIndexEntry(dirRef, name)
            if (dataLcn >= 0) mftMgr.freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) mftMgr.freeMultiClusters(multiRuns)
            mftMgr.freeMftRecord(newRef)
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

    /**
     * 组装一条 FILE 记录（明文，含 $STD_INFO + $FILE_NAME + $DATA + $END）。
     * [resident]=true 时 $DATA 驻留（数据在记录内）；否则非驻留（单 run 指向 [dataLcn]）。
     */
    private fun buildFileRecord(
        recordNo: Long, parentRef: Long, name: String, bytes: ByteArray,
        resident: Boolean, dataLcn: Long, dataClusters: Long,
    ): ByteArray? {
        val rec = ByteArray(recordSize)
        val sectorCount = recordSize / codec.bootSectorSize()
        val usaCount = sectorCount + 1
        val usaOff = 0x30
        // FILE 记录头。
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, usaOff)                 // USA 偏移
        putU16(rec, 6, usaCount)               // USA 项数（含 USN）
        putU64(rec, 8, mftMgr.nextLsn())              // $LogFile LSN（递增，Windows 期望非零且单调）
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
        val sectorCount = recordSize / codec.bootSectorSize()
        val usaCount = sectorCount + 1
        val usaOff = 0x30
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, usaOff)
        putU16(rec, 6, usaCount)
        putU64(rec, 8, mftMgr.nextLsn())              // $LogFile LSN（递增）
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
        // security_id（内容偏移 0x34）指向 $Secure 的共享 SD（0x100）→ 运行时新建文件也带可解析
        //   安全描述符，手动 chkdsk 不再逐个补 ACL。owner_id/quota/usn 留 0（合法）。
        putU32(rec, off + hdr + 0x34, NtfsSecure.FIRST_SECURITY_ID.toLong())
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
        putU16(rec, off + 12, 0)               // flags（0x0C，非压缩/加密/稀疏）——旧码误把 attr-id 写这里
        putU16(rec, off + 14, 1)               // attr instance id（0x0E），唯一：STD=0 / $FILE_NAME=1 / $DATA=6
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
        putU16(rec, off + 12, 0)               // flags（0x0C，非压缩/加密/稀疏）
        putU16(rec, off + 14, 6)               // attr instance id（0x0E）
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
        putU16(rec, off + 12, 0)               // flags（0x0C）
        putU16(rec, off + 14, 6)               // attr instance id（0x0E）
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
        putU16(rec, off + 12, 0)               // flags（0x0C）
        putU16(rec, off + 14, 6)               // attr instance id（0x0E）
        putU64(rec, off + 0x10, 0L)            // 起始 VCN
        putU64(rec, off + 0x18, totalClusters - 1)  // 结束 VCN
        putU16(rec, off + 0x20, 0x40)          // runs 偏移
        putU64(rec, off + 0x28, allocSize)     // 分配大小
        putU64(rec, off + 0x30, realSize)      // 真实大小
        putU64(rec, off + 0x38, realSize)      // 初始化大小
        System.arraycopy(runBytes, 0, rec, off + 0x40, runBytes.size)
        return off + total
    }

    private fun writeClustersData(lcn: Long, bytes: ByteArray) {
        val logical = lcn * clusterSize
        // 整簇写：不足一簇的尾部补零。
        val full = ByteArray(((bytes.size + clusterSize - 1) / clusterSize) * clusterSize)
        System.arraycopy(bytes, 0, full, 0, bytes.size)
        reader.write(logical, full, 0, full.size)
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
            reader.write(logical, block, 0, block.size)
            off += chunk
        }
    }

    // ================= 文件删 =================

    /**
     * 删除目录 [dirRef] 下的文件 [name]。释放其数据簇 + MFT 记录 + 父目录索引项。
     * 仅支持 $INDEX_ROOT 内的项（与 insert 对称）；其余拒绝。
     */
    internal fun ntfsDeleteFile(dirRef: Long, name: String): Boolean {
        // 先找到目标 MFT 记录号。
        val target = listDirEntriesWithRef(dirRef).firstOrNull { it.second == name }?.first ?: return false
        val rec = mftMgr.readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        // 先在内存中解析非驻留 $DATA 的 run 列表，但不动盘（延迟到最后释放）。
        val pendingRuns = ArrayList<Pair<Long, Long>>()
        val data = findAttr(attrs, ATTR_DATA)
        if (data != null && data.nonResident) {
            val runs = decodeRuns(data.recordBuf, data.runsOffset)
            for (run in runs) if (!run.sparse) pendingRuns.add(Pair(run.lcn, run.length))
        }
        // 第一个动盘步骤：从父目录删索引项。失败则原盘未变，直接返回。
        if (!index.removeIndexEntry(dirRef, name)) return false
        // 索引项已成功删除，文件已不可达。标记 FILE 记录不再使用（清 in-use 标志）+ 释放 MFT 位。
        val flags = u16(rec, 0x16) and FLAG_IN_USE.inv()
        val nr = rec.copyOf()
        putU16(nr, 0x16, flags)
        // 序列号 +1（NTFS 删除惯例）。
        putU16(nr, 16, (u16(rec, 16) + 1) and 0xFFFF)
        // 写回 FILE 记录（清 IN_USE + 序列号+1）。失败则中止：不释放 MFT 位、不释放 $DATA 簇。
        // 此时 removeIndexEntry 已使文件不可达，簇仍占位（仅空间泄漏，chkdsk 可回收），
        // 避免 MFT 位与簇被提前释放而复用，导致两文件交叉损坏。
        if (!mftMgr.writeMftRecord(target, nr)) return false
        mftMgr.freeMftRecord(target)
        // 最后才释放 $DATA 的簇：此前任一步失败都不会导致簇被提前释放而复用。
        for (run in pendingRuns) mftMgr.freeClusters(run.first, run.second)
        return true
    }

    /** 目录条目带 MFT 记录号（删除定位用）。 */
    internal fun listDirEntriesWithRef(dirRef: Long): List<Pair<Long, String>> {
        val out = ArrayList<Pair<Long, String>>()
        for (e in index.listDirEntries(dirRef)) out.add(Pair(e.firstCluster, e.name))
        return out
    }

    // ================= 目录操作（W15）=================

    /** UI 句柄 < 16 视为根目录（与 listDir/writeFile 同一规则）。 */
    internal fun normDir(ref: Long): Long = if (ref < 16) MFT_ROOT_DIR else ref

    /**
     * 建子目录 [name] 于 [dirRef]。成功返回新目录 MFT 记录号（>0）；失败返回 0。
     * 流程：allocMftRecord → buildDirRecord（含 $INDEX_ROOT 空树）→ writeMftRecord
     *   → insertIndexEntry（复用 W4）。任何步骤失败回滚已分配的 MFT 记录。
     */
    internal fun ntfsMkDir(dirRef: Long, name: String): Long {
        if (name.isEmpty() || name.length > 255) return 0L
        if (index.listDirEntries(dirRef).any { it.name.equals(name, ignoreCase = false) }) return 0L
        val newRef = mftMgr.allocMftRecord()
        if (newRef < 0) return 0L
        val rec = buildDirRecord(newRef, dirRef, name)
        if (rec == null) { mftMgr.freeMftRecord(newRef); return 0L }
        if (!mftMgr.writeMftRecord(newRef, rec)) { mftMgr.freeMftRecord(newRef); return 0L }
        val fnContent = buildFileNameForIndex(0L, dirRef, name, 0L, 0L, isDir = true)
        if (!index.insertIndexEntry(dirRef, fnContent, newRef)) {
            val bad = rec.copyOf()
            putU16(bad, 0x16, u16(rec, 0x16) and FLAG_IN_USE.inv())
            putU16(bad, 16, (u16(rec, 16) + 1) and 0xFFFF)
            mftMgr.writeMftRecord(newRef, bad)
            mftMgr.freeMftRecord(newRef)
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
        val sectorCount = recordSize / codec.bootSectorSize()
        val usaCount = sectorCount + 1
        val usaOff = 0x30
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, usaOff)
        putU16(rec, 6, usaCount)
        putU64(rec, 8, mftMgr.nextLsn())              // $LogFile LSN（递增）
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
        off = index.writeEmptyIndexRootAttr(rec, off, 2)
        if (off < 0) return null
        if (off + 8 > recordSize) return null
        putU32(rec, off, ATTR_END)
        putU32(rec, 0x18, (off + 8).toLong())
        putU32(rec, 0x1C, recordSize.toLong())
        return rec
    }

    /**
     * 重命名 [dirRef] 下 [oldName] 为 [newName]。
     * 改目标 FILE 记录的 $FILE_NAME 属性（保留 parentRef/时间/size，仅换名）
     *   + 父目录索引项删旧名插新名。保守拒绝：新名已存在 / 名超长 / 记录放不下。
     */
    internal fun ntfsRename(dirRef: Long, oldName: String, newName: String): Boolean {
        if (newName.isEmpty() || newName.length > 255) return false
        if (oldName == newName) return true
        val target = listDirEntriesWithRef(dirRef).firstOrNull { it.second == oldName }?.first ?: return false
        if (index.listDirEntries(dirRef).any { it.name.equals(newName, ignoreCase = false) }) return false
        val rec = mftMgr.readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        val fnAttr = findAttr(attrs, ATTR_FILE_NAME) ?: return false
        val newRec = rewriteFileNameAttr(rec, fnAttr, newName) ?: return false
        if (!mftMgr.writeMftRecord(target, newRec)) return false
        if (!index.removeIndexEntry(dirRef, oldName)) {
            val rolled = rewriteFileNameAttr(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, oldName)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
            return false
        }
        val realSize = readDataRealSize(attrs)
        val allocSize = readDataAllocSize(attrs)
        val isDir = (u16(rec, 0x16) and FLAG_DIRECTORY) != 0
        val fnContent = buildFileNameForIndex(0L, dirRef, newName, realSize, allocSize, isDir)
        if (!index.insertIndexEntry(dirRef, fnContent, target)) {
            val oldFn = buildFileNameForIndex(0L, dirRef, oldName, realSize, allocSize, isDir)
            index.insertIndexEntry(dirRef, oldFn, target)
            val rolled = rewriteFileNameAttr(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, oldName)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
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
    internal fun ntfsMove(srcDirRef: Long, name: String, dstDirRef: Long): Boolean {
        if (srcDirRef == dstDirRef) return true
        val target = listDirEntriesWithRef(srcDirRef).firstOrNull { it.second == name }?.first ?: return false
        if (index.listDirEntries(dstDirRef).any { it.name.equals(name, ignoreCase = false) }) return false
        val rec = mftMgr.readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        val fnAttr = findAttr(attrs, ATTR_FILE_NAME) ?: return false
        val newRec = rewriteFileNameParentRef(rec, fnAttr, dstDirRef) ?: return false
        if (!mftMgr.writeMftRecord(target, newRec)) return false
        if (!index.removeIndexEntry(srcDirRef, name)) {
            val rolled = rewriteFileNameParentRef(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, srcDirRef)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
            return false
        }
        val realSize = readDataRealSize(attrs)
        val allocSize = readDataAllocSize(attrs)
        val isDir = (u16(rec, 0x16) and FLAG_DIRECTORY) != 0
        val fnContent = buildFileNameForIndex(0L, dstDirRef, name, realSize, allocSize, isDir)
        if (!index.insertIndexEntry(dstDirRef, fnContent, target)) {
            val rolled = rewriteFileNameParentRef(newRec, findAttr(parseAttrs(newRec), ATTR_FILE_NAME)!!, srcDirRef)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
            val oldFn = buildFileNameForIndex(0L, srcDirRef, name, realSize, allocSize, isDir)
            index.insertIndexEntry(srcDirRef, oldFn, target)
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
    internal fun ntfsRmDir(dirRef: Long, name: String, recursive: Boolean): Boolean {
        val target = listDirEntriesWithRef(dirRef).firstOrNull { it.second == name }?.first ?: return false
        val rec = mftMgr.readMftRecord(target) ?: return false
        if ((u16(rec, 0x16) and FLAG_DIRECTORY) == 0) return false
        val children = index.listDirEntries(target)
        if (children.isNotEmpty() && !recursive) return false
        if (recursive) {
            for (c in children) {
                if (c.isDirectory) ntfsRmDir(target, c.name, true)
                else ntfsDeleteFile(target, c.name)
            }
            if (index.listDirEntries(target).isNotEmpty()) return false
        }
        if (!index.removeIndexEntry(dirRef, name)) return false
        val attrs = parseAttrs(rec)
        val alloc = findAttr(attrs, ATTR_INDEX_ALLOCATION, "\$I30")
        if (alloc != null && alloc.nonResident) {
            val runs = decodeRuns(alloc.recordBuf, alloc.runsOffset)
            for (run in runs) if (!run.sparse) mftMgr.freeClusters(run.lcn, run.length)
        }
        val nr = rec.copyOf()
        putU16(nr, 0x16, u16(rec, 0x16) and FLAG_IN_USE.inv())
        putU16(nr, 16, (u16(rec, 16) + 1) and 0xFFFF)
        mftMgr.writeMftRecord(target, nr)
        mftMgr.freeMftRecord(target)
        return true
    }

    // ================= mount 辅助 =================

    /** 读卷标（$Volume 记录的 $VOLUME_NAME 属性）。无卷标返回空串。 */
    internal fun readVolumeLabel(): String {
        val rec = mftMgr.readMftRecord(MFT_VOLUME) ?: return ""
        val attrs = parseAttrs(rec)
        val vn = findAttr(attrs, ATTR_VOLUME_NAME) ?: return ""
        if (!vn.nonResident) {
            val v = vn.residentValue()
            val sb = StringBuilder()
            var k = 0
            while (k + 1 < v.size) { sb.append(u16(v, k).toChar()); k += 2 }
            return sb.toString()
        }
        return ""
    }
}
