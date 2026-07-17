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
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.buildFileNameForIndex
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.planFileNames
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

        // 规划 1~2 个 $FILE_NAME（合法 8.3 → 单项 ns=3；非 8.3 → 长名 ns=1 + DOS 短名 ns=2）。
        val existingShortNames = index.listDosShortNamesWithRef(dirRef).map { it.first }.toSet()
        val plan = planFileNames(name, existingShortNames)

        // 分配新 MFT 记录号。
        val newRef = mftMgr.allocMftRecord()
        if (newRef < 0) return false

        // 决定 $DATA 驻留 / 非驻留：能塞进记录剩余空间就驻留，否则连续分配簇。
        // 记录布局预算：头(56) + $STD_INFO(约72) + 1~2×$FILE_NAME + $DATA头 + $END(8)。
        val totalFnAttrLen = plan.sumOf { align8(0x18 + 0x42 + it.first.length * 2) }
        val stdAttrLen = align8(0x18 + 0x48)                 // $STANDARD_INFORMATION 常规 0x48 内容
        val headerAndFixed = 0x38 + 8 /*USA*/ + stdAttrLen + totalFnAttrLen + 8 /*$END*/
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
        val allocSize = allocForIndex(resident, bytes.size.toLong(), dataClusters)
        val rec = if (multiRuns != null) {
            buildFileRecordMulti(newRef, dirRef, plan, bytes, multiRuns, bytes.size.toLong())
        } else {
            buildFileRecord(newRef, dirRef, plan, bytes, resident, dataLcn, dataClusters)
        }
        if (rec == null) {
            if (dataLcn >= 0) mftMgr.freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) mftMgr.freeMultiClusters(multiRuns)
            mftMgr.freeMftRecord(newRef)
            return false
        }

        // 先把索引项插进父目录（1~2 项，可能因放不下而拒绝——此时回滚，不留孤儿记录）。
        val inserted = ArrayList<String>()
        var allInserted = true
        for ((nm, ns) in plan) {
            val fnEntry = buildFileNameForIndex(newRef, dirRef, nm, bytes.size.toLong(), allocSize, false, ns)
            if (!index.insertIndexEntry(dirRef, fnEntry, newRef)) {
                allInserted = false
                break
            }
            inserted.add(nm)
        }
        if (!allInserted) {
            // 回滚已插入的索引项（removeIndexEntry 按 mftRef 删全部孪生项）。
            for (nm in inserted) index.removeIndexEntry(dirRef, nm)
            if (dataLcn >= 0) mftMgr.freeClusters(dataLcn, dataClusters)
            if (multiRuns != null) mftMgr.freeMultiClusters(multiRuns)
            mftMgr.freeMftRecord(newRef)
            return false
        }

        // 索引插入成功后再落 FILE 记录（顺序：先索引可回滚，记录落盘即生效）。
        if (!mftMgr.writeMftRecord(newRef, rec)) {
            // 记录写失败：尽力回滚索引 + 资源。
            for (nm in inserted) index.removeIndexEntry(dirRef, nm)
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
     * 组装一条 FILE 记录（明文，含 $STD_INFO + 1~2×$FILE_NAME + $DATA + $END）。
     * [plan] 由 [planFileNames] 生成：合法 8.3 名 → 单项 ns=3(link=1)；非 8.3 → 长名+DOS短名(link=2)。
     * [resident]=true 时 $DATA 驻留（数据在记录内）；否则非驻留（单 run 指向 [dataLcn]）。
     */
    private fun buildFileRecord(
        recordNo: Long, parentRef: Long, plan: List<Pair<String, Int>>, bytes: ByteArray,
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
        putU16(rec, 18, plan.size)             // 硬链接数 = $FILE_NAME 属性数（1 或 2）
        val firstAttrOff = align8(usaOff + usaCount * 2)
        putU16(rec, 20, firstAttrOff)          // 首属性偏移
        putU16(rec, 22, FLAG_IN_USE)           // 标志：使用中（非目录）
        putU16(rec, 0x28, 7)   // next-attr-id (> max used id=6: STD=0/FN=1..2/DATA=6)
        putU16(rec, 0x2A, 0)
        putU32(rec, 0x2C, recordNo)            // 本记录号

        var off = firstAttrOff
        // --- $STANDARD_INFORMATION (0x10, 驻留) ---
        off = writeStdInfo(rec, off)
        // --- $FILE_NAME (0x30, 驻留, 1~2 个) ---
        off = writeFileNameAttrs(rec, off, parentRef, plan, bytes.size.toLong(),
            if (resident) align8Long(bytes.size.toLong()) else dataClusters * clusterSize, isDir = false)
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
        recordNo: Long, parentRef: Long, plan: List<Pair<String, Int>>, bytes: ByteArray,
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
        putU16(rec, 18, plan.size)             // 硬链接数 = $FILE_NAME 属性数（1 或 2）
        val firstAttrOff = align8(usaOff + usaCount * 2)
        putU16(rec, 20, firstAttrOff)
        putU16(rec, 22, FLAG_IN_USE)
        putU16(rec, 0x28, 7)
        putU16(rec, 0x2A, 0)
        putU32(rec, 0x2C, recordNo)
        var off = firstAttrOff
        off = writeStdInfo(rec, off)
        val totalClusters = runs.sumOf { it.length }
        off = writeFileNameAttrs(rec, off, parentRef, plan, realSize, totalClusters * clusterSize, isDir = false)
        if (off < 0) return null
        off = writeNonResidentDataMulti(rec, off, runs, realSize)
        if (off < 0) return null
        if (off + 8 > recordSize) return null
        putU32(rec, off, ATTR_END)
        putU32(rec, 0x18, (off + 8).toLong())
        putU32(rec, 0x1C, recordSize.toLong())
        return rec
    }

    /** 写 $STANDARD_INFORMATION，返回下一属性偏移。[isDir]=true 时置目录位 0x10000000。 */
    private fun writeStdInfo(rec: ByteArray, off: Int, isDir: Boolean = false): Int {
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
        // 目录 = I30_INDEX_PRESENT(0x10000000)；文件 = ARCHIVE(0x20)。目录写 ARCHIVE 与记录头
        //   FLAG_DIRECTORY + $I30 矛盾 → chkdsk 报「文件属性不一致」并重写。与 $FILE_NAME 0x38 同步。
        putU32(rec, off + hdr + 0x20, if (isDir) NtfsFormatter.FILE_ATTR_I30_INDEX_PRESENT else 0x20L)
        // security_id（内容偏移 0x34）指向 $Secure 的共享 SD（0x100）→ 运行时新建文件也带可解析
        //   安全描述符，手动 chkdsk 不再逐个补 ACL。owner_id/quota/usn 留 0（合法）。
        putU32(rec, off + hdr + 0x34, NtfsSecure.FIRST_SECURITY_ID.toLong())
        return off + total
    }

    /**
     * 写 1~2 个 $FILE_NAME 属性（由 [plan] 决定）。返回下一属性偏移；越界返回 -1。
     * 每个属性的 attr-instance-id 从 1 递增（STD=0, FN=1, FN2=2, DATA=6）。
     */
    private fun writeFileNameAttrs(rec: ByteArray, off: Int, parentRef: Long,
                                   plan: List<Pair<String, Int>>,
                                   realSize: Long, allocSize: Long, isDir: Boolean): Int {
        var p = off
        var attrId = 1
        for ((nm, ns) in plan) {
            p = writeFileNameAttr(rec, p, parentRef, nm, realSize, allocSize, isDir, ns, attrId)
            if (p < 0) return -1
            attrId++
        }
        return p
    }

    /** 写单个 $FILE_NAME 属性，返回下一属性偏移；越界返回 -1。 */
    private fun writeFileNameAttr(rec: ByteArray, off: Int, parentRef: Long, name: String,
                                  realSize: Long, allocSize: Long, isDir: Boolean,
                                  ns: Int, attrId: Int): Int {
        val fn = buildFileNameForIndex(0L, parentRef, name, realSize, allocSize, isDir, ns)
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
        putU16(rec, off + 12, 0)               // flags（0x0C，非压缩/加密/稀疏）
        putU16(rec, off + 14, attrId)          // attr instance id（0x0E）
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
     * 删除目录 [dirRef] 下的文件 [name]。释放其数据簇 + MFT 记录 + 父目录索引项（含孪生 DOS 短名项）。
     * removeIndexEntry 按 mftRef 删全部孪生项，无需改造。
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
     * 流程：planFileNames → allocMftRecord → buildDirRecord（含 $INDEX_ROOT 空树）
     *   → writeMftRecord → insertIndexEntry（1~2 项）。任何步骤失败回滚已分配的 MFT 记录。
     */
    internal fun ntfsMkDir(dirRef: Long, name: String): Long {
        if (name.isEmpty() || name.length > 255) return 0L
        if (index.listDirEntries(dirRef).any { it.name.equals(name, ignoreCase = false) }) return 0L
        val existingShortNames = index.listDosShortNamesWithRef(dirRef).map { it.first }.toSet()
        val plan = planFileNames(name, existingShortNames)
        val newRef = mftMgr.allocMftRecord()
        if (newRef < 0) return 0L
        val rec = buildDirRecord(newRef, dirRef, plan)
        if (rec == null) { mftMgr.freeMftRecord(newRef); return 0L }
        if (!mftMgr.writeMftRecord(newRef, rec)) { mftMgr.freeMftRecord(newRef); return 0L }
        // 插入 1~2 个索引项（长名 + DOS 短名孪生项）。
        val inserted = ArrayList<String>()
        var allInserted = true
        for ((nm, ns) in plan) {
            val fnContent = buildFileNameForIndex(0L, dirRef, nm, 0L, 0L, isDir = true, ns = ns)
            if (!index.insertIndexEntry(dirRef, fnContent, newRef)) {
                allInserted = false
                break
            }
            inserted.add(nm)
        }
        if (!allInserted) {
            // 回滚已插入索引项 + 标记记录未用。
            for (nm in inserted) index.removeIndexEntry(dirRef, nm)
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
     *   + 1~2×$FILE_NAME（isDir）+ $INDEX_ROOT 空树（$I30，末项 LAST）+ $END。
     * 与 [buildFileRecord] 区别：无 $DATA，多 $INDEX_ROOT；记录头标志含 DIRECTORY。
     */
    private fun buildDirRecord(recordNo: Long, parentRef: Long, plan: List<Pair<String, Int>>): ByteArray? {
        val rec = ByteArray(recordSize)
        val sectorCount = recordSize / codec.bootSectorSize()
        val usaCount = sectorCount + 1
        val usaOff = 0x30
        rec[0] = 'F'.code.toByte(); rec[1] = 'I'.code.toByte(); rec[2] = 'L'.code.toByte(); rec[3] = 'E'.code.toByte()
        putU16(rec, 4, usaOff)
        putU16(rec, 6, usaCount)
        putU64(rec, 8, mftMgr.nextLsn())              // $LogFile LSN（递增）
        putU16(rec, 16, 1)
        putU16(rec, 18, plan.size)             // 硬链接数 = $FILE_NAME 属性数（1 或 2）
        val firstAttrOff = align8(usaOff + usaCount * 2)
        putU16(rec, 20, firstAttrOff)
        putU16(rec, 22, FLAG_IN_USE or FLAG_DIRECTORY)
        putU16(rec, 0x28, 7)
        putU16(rec, 0x2A, 0)
        putU32(rec, 0x2C, recordNo)
        var off = firstAttrOff
        off = writeStdInfo(rec, off, isDir = true)
        off = writeFileNameAttrs(rec, off, parentRef, plan, 0L, 0L, isDir = true)
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
     * 改目标 FILE 记录的 $FILE_NAME 属性区（保留 parentRef/时间/size，仅换名+ns 策略）
     *   + 父目录索引项删旧名（含孪生）插新名（1~2 项）。保守拒绝：新名已存在 / 名超长 / 记录放不下。
     */
    internal fun ntfsRename(dirRef: Long, oldName: String, newName: String): Boolean {
        if (newName.isEmpty() || newName.length > 255) return false
        if (oldName == newName) return true
        val target = listDirEntriesWithRef(dirRef).firstOrNull { it.second == oldName }?.first ?: return false
        if (index.listDirEntries(dirRef).any { it.name.equals(newName, ignoreCase = false) }) return false
        val rec = mftMgr.readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        val realSize = readDataRealSize(attrs)
        val allocSize = readDataAllocSize(attrs)
        val isDir = (u16(rec, 0x16) and FLAG_DIRECTORY) != 0

        // 保留旧 plan 供回滚。
        val oldPlan = readFileNamePlan(rec)

        // 规划新名（排除自身的 DOS 短名，避免 ~N 碰撞自身旧短名）。
        val existingShortNames = index.listDosShortNamesWithRef(dirRef)
            .filter { it.second != target }
            .map { it.first }.toSet()
        val newPlan = planFileNames(newName, existingShortNames)

        // 重写 FN 区（1~2 旧 → 1~2 新，平移后续属性，更新 link count）。
        val newRec = rewriteFileNameSection(rec, dirRef, newPlan, realSize, allocSize, isDir) ?: return false
        if (!mftMgr.writeMftRecord(target, newRec)) return false

        // 删旧索引项（removeIndexEntry 按 mftRef 删全部孪生）。
        if (!index.removeIndexEntry(dirRef, oldName)) {
            // 回滚记录。
            val rolled = rewriteFileNameSection(newRec, dirRef, oldPlan, realSize, allocSize, isDir)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
            return false
        }

        // 插新索引项（1~2 项）。
        val inserted = ArrayList<String>()
        var allInserted = true
        for ((nm, ns) in newPlan) {
            val fnContent = buildFileNameForIndex(0L, dirRef, nm, realSize, allocSize, isDir, ns)
            if (!index.insertIndexEntry(dirRef, fnContent, target)) {
                allInserted = false
                break
            }
            inserted.add(nm)
        }
        if (!allInserted) {
            // 回滚：删已插新项 → 重插旧项 → 回滚记录。
            for (nm in inserted) index.removeIndexEntry(dirRef, nm)
            for ((nm, ns) in oldPlan) {
                val fnContent = buildFileNameForIndex(0L, dirRef, nm, realSize, allocSize, isDir, ns)
                index.insertIndexEntry(dirRef, fnContent, target)
            }
            val rolled = rewriteFileNameSection(newRec, dirRef, oldPlan, realSize, allocSize, isDir)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
            return false
        }
        return true
    }

    /**
     * 重写 $FILE_NAME 属性区：移除所有旧 $FILE_NAME（1~2 个），写入 [plan] 指定的新 FN 属性，
     * 平移后续属性（$DATA/$INDEX_ROOT 等），更新硬链接数（=plan.size）。放不下返回 null。
     * 保留 parentRef / 4 时间戳 / allocSize / realSize / flags / reparse（由 [plan] 的 ns 决定 namespace）。
     */
    private fun rewriteFileNameSection(
        rec: ByteArray, parentRef: Long, plan: List<Pair<String, Int>>,
        realSize: Long, allocSize: Long, isDir: Boolean,
    ): ByteArray? {
        val recUsed = u32(rec, 0x18).toInt()

        // 定位 FN 属性区范围（$FILE_NAME 在记录中连续：STD_INFO 之后、$DATA/$INDEX_ROOT 之前）。
        var firstFnOff = -1
        var lastFnEnd = -1
        var off = u16(rec, 0x14)
        while (off + 8 <= recUsed && off + 8 <= rec.size) {
            val type = u32(rec, off)
            if (type == ATTR_END) break
            val totalLen = u32(rec, off + 4).toInt()
            if (totalLen <= 0 || off + totalLen > recUsed) break
            if (type == ATTR_FILE_NAME) {
                if (firstFnOff < 0) firstFnOff = off
                lastFnEnd = off + totalLen
            }
            off += totalLen
        }
        if (firstFnOff < 0) return null

        val newFnTotal = plan.sumOf { align8(0x18 + 0x42 + it.first.length * 2) }
        val oldFnTotal = lastFnEnd - firstFnOff
        val delta = newFnTotal - oldFnTotal
        if (recUsed + delta > recordSize) return null

        val newRec = rec.copyOf()
        // 平移 FN 区后续属性。
        val afterOff = lastFnEnd
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
        // 清零旧 FN 区（防止新 FN 比旧短时残留）。
        for (i in firstFnOff until firstFnOff + newFnTotal) {
            if (i < recordSize) newRec[i] = 0
        }
        // 写新 FN 属性。
        val writeResult = writeFileNameAttrs(newRec, firstFnOff, parentRef, plan, realSize, allocSize, isDir)
        if (writeResult < 0) return null
        // 更新硬链接数。
        putU16(newRec, 18, plan.size)
        // 更新已用大小。
        putU32(newRec, 0x18, (recUsed + delta).toLong())
        return newRec
    }

    /** 读记录中所有 $FILE_NAME 属性的 (名, namespace)，保留顺序。供 rename/move 回滚用。 */
    private fun readFileNamePlan(rec: ByteArray): List<Pair<String, Int>> {
        val attrs = parseAttrs(rec)
        val out = ArrayList<Pair<String, Int>>()
        for (a in attrs) {
            if (a.type == ATTR_FILE_NAME && a.name.isEmpty() && !a.nonResident) {
                val v = a.residentValue()
                if (v.size >= 0x42) {
                    val nameLen = v[0x40].toInt() and 0xFF
                    val ns = v[0x41].toInt() and 0xFF
                    val sb = StringBuilder(nameLen)
                    for (k in 0 until nameLen) {
                        if (0x42 + k * 2 + 1 < v.size) sb.append(u16(v, 0x42 + k * 2).toChar())
                    }
                    out.add(sb.toString() to ns)
                }
            }
        }
        return out
    }

    /**
     * 同卷内把 [srcDirRef] 下的 [name] 移到 [dstDirRef]。
     * 改 $FILE_NAME 的 parentRef + 重建 FN 区（DOS 短名可能在目标目录冲突 → 重新规划）
     *   + 父目录索引项删旧（含孪生）插新（1~2 项）。不搬数据簇。保守拒绝：目标已存在同名。
     */
    internal fun ntfsMove(srcDirRef: Long, name: String, dstDirRef: Long): Boolean {
        if (srcDirRef == dstDirRef) return true
        val target = listDirEntriesWithRef(srcDirRef).firstOrNull { it.second == name }?.first ?: return false
        if (index.listDirEntries(dstDirRef).any { it.name.equals(name, ignoreCase = false) }) return false
        val rec = mftMgr.readMftRecord(target) ?: return false
        val attrs = parseAttrs(rec)
        val realSize = readDataRealSize(attrs)
        val allocSize = readDataAllocSize(attrs)
        val isDir = (u16(rec, 0x16) and FLAG_DIRECTORY) != 0

        val oldPlan = readFileNamePlan(rec)

        // 在目标目录规划名（DOS 短名可能需重新生成以避免冲突）。
        val existingShortNames = index.listDosShortNamesWithRef(dstDirRef)
            .filter { it.second != target }
            .map { it.first }.toSet()
        val newPlan = planFileNames(name, existingShortNames)

        // 重写 FN 区（新 parentRef + 新 plan）。
        val newRec = rewriteFileNameSection(rec, dstDirRef, newPlan, realSize, allocSize, isDir) ?: return false
        if (!mftMgr.writeMftRecord(target, newRec)) return false

        // 删源目录索引项（含孪生 DOS 短名项）。
        if (!index.removeIndexEntry(srcDirRef, name)) {
            val rolled = rewriteFileNameSection(newRec, srcDirRef, oldPlan, realSize, allocSize, isDir)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
            return false
        }

        // 插目标目录索引项（1~2 项）。
        val inserted = ArrayList<String>()
        var allInserted = true
        for ((nm, ns) in newPlan) {
            val fnContent = buildFileNameForIndex(0L, dstDirRef, nm, realSize, allocSize, isDir, ns)
            if (!index.insertIndexEntry(dstDirRef, fnContent, target)) {
                allInserted = false
                break
            }
            inserted.add(nm)
        }
        if (!allInserted) {
            // 回滚：删目标已插项 → 重插源项 → 回滚记录。
            for (nm in inserted) index.removeIndexEntry(dstDirRef, nm)
            for ((nm, ns) in oldPlan) {
                val fnContent = buildFileNameForIndex(0L, srcDirRef, nm, realSize, allocSize, isDir, ns)
                index.insertIndexEntry(srcDirRef, fnContent, target)
            }
            val rolled = rewriteFileNameSection(newRec, srcDirRef, oldPlan, realSize, allocSize, isDir)
            if (rolled != null) mftMgr.writeMftRecord(target, rolled)
            return false
        }
        return true
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
