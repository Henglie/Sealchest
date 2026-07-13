package com.henglie.sealchest.fs

import com.henglie.sealchest.fs.NtfsRecordCodec.Attr
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_END
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_INDEX_ALLOCATION
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ATTR_INDEX_ROOT
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.INDEX_ENTRY_HAS_SUBNODE
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.INDEX_ENTRY_LAST
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.MFT_ROOT_DIR
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.NS_DOS
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.align8
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.attrOffsetOf
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.buildFileNameForIndex
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.buildIndexEntry
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.buildSubnodeEntry
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.collationCompare
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.decodeRuns
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.encodeSingleRun
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.entryFileName
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.entryMftRef
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.findAttr
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.ntfsTimeToMs
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.parseAttrs
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.parseEntryNames
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.putU16
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.putU32
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.putU64
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.stripToLeafEntry
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u16
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u32
import com.henglie.sealchest.fs.NtfsRecordCodec.Companion.u64

/**
 * NTFS 目录索引管理：读侧遍历、写侧 B+树整树重建、INDX 叶子构造、属性序列化。
 *
 * 从 [NtfsFileSystem] 拆出的索引层。无自身状态。调用 [NtfsMftManager] 读写 MFT 记录
 * 与分配/释放簇，调用 [NtfsRecordCodec] 的 USA 修复与工具方法。
 *
 * 依赖方向：RecordCodec ← MftManager ← Index ← DataOps ← FileSystem。
 */
class NtfsIndex(
    private val mftMgr: NtfsMftManager,
    private val codec: NtfsRecordCodec,
    private val reader: VolumeReader,
    private val boot: NtfsBoot,
) {
    private val recordSize = boot.fileRecordSize
    private val clusterSize = boot.bytesPerCluster

    // ================= 读侧：目录遍历 =================

    /**
     * 收集目录（MFT 记录 [dirRecordNo]）下的索引项 → 子文件 (name, mftRef, isDir, size)。
     * 走 $INDEX_ROOT（驻留）+ $INDEX_ALLOCATION（非驻留 INDX 记录）。
     */
    internal fun listDirEntries(dirRecordNo: Long): List<FsEntry> {
        val rec = mftMgr.readMftRecord(dirRecordNo) ?: return emptyList()
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
                val indx = mftMgr.readFromRuns(runs, pos, idxSize)
                pos += idxSize
                if (indx == null || indx.size < 4) continue
                if (indx[0] != 'I'.code.toByte()) continue   // "INDX" 签名；空块跳过
                codec.applyUsaFixup(indx)
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

    // ================= 写侧：B+树整树重建 =================
    //
    // 策略：insert/delete 统一为「collectAllLeafEntries 全树 → 增/删一项 → rebuildDirIndex 从排序表重建」。
    // 一条路径，一处对处处对。支持 2 层 B+树（root 指针节点 + N 个 INDX 叶子）；3 层（需 root 放不下
    // 全部分隔符）保守拒绝。仅 indexRecordSize>=clusterSize（4096 索引 + 簇<=4096，绝大多数容器）走多叶；
    // 超大簇(idxRecSize<clusterSize)的多叶 VCN 编码复杂，保守拒绝。
    // NTFS 索引是 B-树：分隔符键项提升到 root（带 HAS_SUBNODE+子节点 VCN），不在叶子重复；
    //   读侧遍历 root 键项 + 全叶子项去重，故收集必须含 root 键项。

    /**
     * 把索引项（$FILE_NAME 内容 [fnContent]，指向 [mftRef]）插入目录 [dirRef]。
     * 统一走整树重建：收集全树叶子项 → 加新项 → 排序 → 重建（全驻留/2 层自动选）。
     * >2 层 / 解析异常 → collect 返 null → 保守拒绝。
     * 保守原则：拿不准一律返回 false 不动盘，绝不写坏 B+树。
     */
    internal fun insertIndexEntry(dirRef: Long, fnContent: ByteArray, mftRef: Long): Boolean {
        val rec = mftMgr.readMftRecord(dirRef) ?: return false
        val attrs = parseAttrs(rec)
        val root = findAttr(attrs, ATTR_INDEX_ROOT, "\$I30") ?: return false
        if (root.nonResident) return false
        val newEntry = buildIndexEntry(fnContent, mftRef, hasSubnode = false, isLast = false)

        val collected = collectAllLeafEntries(rec, attrs) ?: return false
        val all = ArrayList(collected)
        all.add(stripToLeafEntry(newEntry))
        all.sortWith(Comparator { a, b -> collationCompare(entryFileName(a), entryFileName(b)) })
        return rebuildDirIndex(dirRef, all)
    }

    /**
     * 从目录 [dirRef] 删除名为 [name] 的索引项（含其 DOS 短名孪生项，按同一 mftRef 一并删）。
     * 走整树重建：收集全树 → 剔除目标 mftRef 的所有项 → 重建。找不到 / >2 层 → false。
     */
    internal fun removeIndexEntry(dirRef: Long, name: String): Boolean {
        val rec = mftMgr.readMftRecord(dirRef) ?: return false
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
            .sortedWith(Comparator { a, b -> collationCompare(entryFileName(a), entryFileName(b)) })
        if (kept.size == all.size) return false   // 没删掉任何项 = 异常
        return rebuildDirIndex(dirRef, kept)
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
                val indx = mftMgr.readFromRuns(runs, pos, idxSize)
                pos += idxSize
                if (indx == null || indx.size < 4 || indx[0] != 'I'.code.toByte()) continue
                codec.applyUsaFixup(indx)
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
        val origRec = mftMgr.readMftRecord(dirRef) ?: return false
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
                if (mftMgr.writeMftRecord(dirRef, rec)) { freeOldIndexAlloc(origAttrs); return true }
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
        // 空尾叶修复：若末项被提升为分隔符致尾叶为空，降回前一叶（不产生空 INDX 记录）
        if (cur.isEmpty() && separators.isNotEmpty()) {
            val lastLeaf = leaves.removeAt(leaves.lastIndex).toMutableList()
            lastLeaf.add(separators.removeAt(separators.lastIndex))
            leaves.add(lastLeaf)
        } else {
            leaves.add(cur)
        }
        val numLeaves = leaves.size

        // root 大索引内容（分隔符各带子节点 VCN + LAST→末叶 VCN）；放不下 = 需 3 层。
        val cpr = clustersPerIndexRecord()
        val largeRoot = buildLargeRootContent(separators, numLeaves, cpr) ?: return false

        // 组装目录 FILE 记录：非索引属性 + 大 $INDEX_ROOT + $INDEX_ALLOCATION + $BITMAP + END。
        val totalClusters = numLeaves * cpr
        val lcn = mftMgr.allocContiguousClusters(totalClusters)
        if (lcn < 0) return false
        val newRec = base.copyOf()
        val rootId = origIndexRootId(origRec)
        val allocId = maxOf(u16(origRec, 0x28), rootId + 1)
        val bmpId = allocId + 1
        var off = writeIndexRootAttrWith(newRec, baseOff, rootId, largeRoot)
        if (off < 0) { mftMgr.freeClusters(lcn, totalClusters); return false }
        off = writeIndexAllocationAttr(newRec, off, lcn, totalClusters, allocId)
        if (off < 0) { mftMgr.freeClusters(lcn, totalClusters); return false }
        off = writeIndexBitmapMulti(newRec, off, bmpId, numLeaves)
        if (off < 0) { mftMgr.freeClusters(lcn, totalClusters); return false }
        if (off + 8 > recordSize) { mftMgr.freeClusters(lcn, totalClusters); return false }
        putU32(newRec, off, ATTR_END)
        putU32(newRec, 0x18, (off + 8).toLong())
        putU32(newRec, 0x1C, recordSize.toLong())
        putU16(newRec, 0x28, (bmpId + 1) and 0xFFFF)

        // 写各叶子 INDX（VCN = i*cpr），先打 USA。
        for (i in 0 until numLeaves) {
            val vcn = i.toLong() * cpr
            val indx = buildIndxLeafRecord(leaves[i], vcn) ?: run { mftMgr.freeClusters(lcn, totalClusters); return false }
            codec.stampUsa(indx)
            reader.write((lcn + i.toLong() * cpr) * clusterSize, indx, 0, indx.size)
        }
        if (!mftMgr.writeMftRecord(dirRef, newRec)) { mftMgr.freeClusters(lcn, totalClusters); return false }
        freeOldIndexAlloc(origAttrs)   // 先建后拆：新记录写成功才释放旧簇
        return true
    }

    // ---- INDX 叶子记录构造 ----

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

    // ---- $INDEX_ROOT 内容构造 ----

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

    // ---- 属性序列化 ----

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
        putU16(rec, off + 12, 0); putU16(rec, off + 14, attrId)  // flags=0 / instance
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
        putU16(rec, off + 12, 0); putU16(rec, off + 14, attrId)  // flags=0 / instance
        putU64(rec, off + 0x10, 0L)         // start VCN
        putU64(rec, off + 0x18, (clusters - 1))   // end VCN
        putU16(rec, off + 0x20, runOff)     // runs 偏移
        rec[off + 0x22] = 0                 // compression unit
        putU64(rec, off + 0x28, (clusters * clusterSize).toLong())   // allocated size
        putU64(rec, off + 0x30, (clusters * clusterSize).toLong())   // real size
        putU64(rec, off + 0x38, (clusters * clusterSize).toLong())   //initialized size
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
        putU16(rec, off + 12, 0); putU16(rec, off + 14, attrId)  // flags=0 / instance
        putU32(rec, off + 0x10, bmp.size.toLong())   // value length
        putU16(rec, off + 0x14, valOff)               // value offset
        val name = "\$I30"
        for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        System.arraycopy(bmp, 0, rec, off + valOff, bmp.size)
        return off + total
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
        putU16(rec, off + 10, nameOff); putU16(rec, off + 12, 0); putU16(rec, off + 14, attrId)
        putU32(rec, off + 0x10, bmp.size.toLong()); putU16(rec, off + 0x14, valOff)
        val name = "\$I30"; for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        System.arraycopy(bmp, 0, rec, off + valOff, bmp.size)
        return off + total
    }

    /** 把 $INDEX_ROOT 内容 [content] 写成属性（驻留，名 $I30），返回下一偏移；越界 -1。 */
    private fun writeIndexRootAttrWith(rec: ByteArray, off: Int, attrId: Int, content: ByteArray): Int {
        val nameLen = 4; val nameOff = 0x18; val valOff = nameOff + nameLen * 2   // 0x20
        val total = align8(valOff + content.size)
        if (off + total > recordSize) return -1
        putU32(rec, off, ATTR_INDEX_ROOT); putU32(rec, off + 4, total.toLong())
        rec[off + 8] = 0; rec[off + 9] = nameLen.toByte()
        putU16(rec, off + 10, nameOff); putU16(rec, off + 12, 0); putU16(rec, off + 14, attrId)
        putU32(rec, off + 0x10, content.size.toLong()); putU16(rec, off + 0x14, valOff)
        val name = "\$I30"; for (k in name.indices) putU16(rec, off + nameOff + k * 2, name[k].code)
        System.arraycopy(content, 0, rec, off + valOff, content.size)
        return off + total
    }

    /**
     * 写空 $INDEX_ROOT 属性（$I30，驻留，小索引）：INDEX_ROOT头 + INDEX_HEADER
     *   + 末项（LAST，无内容，无子节点，0x10 字节）。返回下一偏移；越界 -1。
     * 与 [writeLargeIndexRootAttr] 区别：flags=0（小索引），末项无 HAS_SUBNODE。
     */
    internal fun writeEmptyIndexRootAttr(rec: ByteArray, off: Int, attrId: Int): Int {
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
        putU16(rec, off + 12, 0); putU16(rec, off + 14, attrId)  // flags=0 / instance
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

    // ---- 辅助 ----

    /** 原 $INDEX_ROOT 的属性 id（复用，无则 2）。 */
    private fun origIndexRootId(origRec: ByteArray): Int {
        val o = attrOffsetOf(origRec, ATTR_INDEX_ROOT, "\$I30") ?: return 2
        return u16(origRec, o + 0x0E)
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
        for (run in runs) if (!run.sparse) mftMgr.freeClusters(run.lcn, run.length)
    }

    // ---- 内存自测（去险：NTFS 是死代码没法真机跑，自测在编译期揪层布局 bug）----

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
                .sortedWith(Comparator { a, b -> collationCompare(entryFileName(a), entryFileName(b)) })
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
                .sortedWith(Comparator { a, b -> collationCompare(entryFileName(a), entryFileName(b)) })
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
                .sortedWith(Comparator { a, b -> collationCompare(entryFileName(a), entryFileName(b)) })
            val content = buildResidentRootContent(entries)
            val flags = u32(content, 0x1C).toInt()
            val ok = flags == 0   // 小索引 flags=0（无 INDEX_ALLOCATION）
            sb.append("[驻留 flags] ").append(if (ok) "PASS" else "FAIL flags=$flags").append("\n")
        }
        return sb.toString()
    }
}
