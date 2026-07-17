package com.henglie.sealchest.fs

/**
 * NTFS 记录编解码工具（无状态 / 仅持 [boot] 的 USA 相关参数）。
 *
 * 从 [NtfsFileSystem] 拆出的纯工具层：字节读写、时间转换、USA 修复 / 打签名、
 * 属性解析、data run 编解码、索引项原语、$FILE_NAME body 构造。
 *
 * 依赖方向的最底层：RecordCodec ← MftManager ← Index ← DataOps ← FileSystem。
 * 纯工具方法放 [companion object]（调用方 star-import 即可裸名用），
 * 需 [boot.bytesPerSector] 的 USA 方法为实例方法。
 */
class NtfsRecordCodec(private val boot: NtfsBoot) {

    // ---- 有状态方法（需 boot.bytesPerSector）----

    /**
     * USA 修复：记录头偏移 4 = USN 偏移（u16），偏移 6 = USN 计数（u16，含 1 个序列号
     * + N 个扇区末原值）。把每扇区最后 2 字节从数组恢复。
     */
    fun applyUsaFixup(buf: ByteArray): Boolean {
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

    /** USA 打签名：递增 USN → 扇区末 2 字节存入 USA 数组 → 扇区末写 USN。 */
    fun stampUsa(buf: ByteArray) {
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

    fun bootSectorSize() = boot.bytesPerSector

    // ---- 属性 / data run 数据类（class 级，供外部引用 NtfsRecordCodec.Attr / .DataRun）----

    internal class Attr(
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

    internal class DataRun(val length: Long, val lcn: Long, val sparse: Boolean)

    companion object {

        // ---- 固定 MFT 记录号 ----
        const val MFT_ROOT_DIR = 5L          // 根目录 "."
        const val MFT_VOLUME = 3L            // $Volume（卷标在此）

        // ---- 属性类型 ----
        const val ATTR_STANDARD_INFO = 0x10L
        const val ATTR_FILE_NAME = 0x30L
        const val ATTR_VOLUME_NAME = 0x60L
        const val ATTR_VOLUME_INFO = 0x70L
        const val ATTR_DATA = 0x80L
        const val ATTR_INDEX_ROOT = 0x90L
        const val ATTR_INDEX_ALLOCATION = 0xA0L
        const val ATTR_END = 0xFFFFFFFFL

        // ---- $FILE_NAME 命名空间（偏移 0x41 处 1 字节）----
        const val NS_POSIX = 0               // POSIX（大小写敏感，可含除 NUL/ '/' 外任意字符）
        const val NS_WIN32 = 1               // Win32 长名（非 8.3 名须配 ns=2 DOS 短名孪生项）
        const val NS_DOS = 2                 // 纯 DOS 短名（8.3），列目录时跳过
        const val NS_WIN32_AND_DOS = 3       // 既是 Win32 又是 DOS 名（合法 8.3 名单项用此）

        // ---- FILE 记录标志（记录头偏移 0x16）----
        const val FLAG_IN_USE = 0x0001
        const val FLAG_DIRECTORY = 0x0002

        // ---- $VOLUME_INFORMATION 属性（0x70，驻留）内容布局：0x00 保留 / 0x08 Major / 0x09 Minor / 0x0A flags(u16) ----
        const val VOLUME_FLAG_DIRTY = 0x01

        // ---- 索引项标志 ----
        const val INDEX_ENTRY_HAS_SUBNODE = 0x01
        const val INDEX_ENTRY_LAST = 0x02

        const val NTFS_EPOCH_DIFF_MS = 11644473600000L  // 1601→1970 毫秒差

        // ---- 小工具 ----
        fun u16(b: ByteArray, o: Int) =
            (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

        fun u32(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF).toLong()) or
            ((b[o + 1].toInt() and 0xFF).toLong() shl 8) or
            ((b[o + 2].toInt() and 0xFF).toLong() shl 16) or
            ((b[o + 3].toInt() and 0xFF).toLong() shl 24)

        fun u64(b: ByteArray, o: Int): Long {
            var v = 0L
            for (k in 0 until 8) v = v or ((b[o + k].toInt() and 0xFF).toLong() shl (8 * k))
            return v
        }

        fun putU16(b: ByteArray, o: Int, v: Int) {
            b[o] = (v and 0xFF).toByte(); b[o + 1] = ((v shr 8) and 0xFF).toByte()
        }

        fun putU32(b: ByteArray, o: Int, v: Long) {
            for (k in 0 until 4) b[o + k] = ((v ushr (8 * k)) and 0xFF).toByte()
        }

        fun putU64(b: ByteArray, o: Int, v: Long) {
            for (k in 0 until 8) b[o + k] = ((v ushr (8 * k)) and 0xFF).toByte()
        }

        /** 属性头对齐（NTFS 属性 8 字节对齐）。 */
        fun align8(v: Int) = (v + 7) and 0x7.inv()

        fun align8Long(v: Long) = (v + 7) and 0x7L.inv()

        // ---- 时间转换 ----

        fun ntfsTimeToMs(t: Long): Long {
            if (t <= 0) return 0
            return t / 10000 - NTFS_EPOCH_DIFF_MS
        }

        fun msToNtfsTime(ms: Long): Long = (ms + NTFS_EPOCH_DIFF_MS) * 10000L

        // ---- 属性解析 ----

        /** 遍历一条 FILE 记录的所有属性。 */
        internal fun parseAttrs(rec: ByteArray): List<Attr> {
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
        internal fun findAttr(attrs: List<Attr>, type: Long, name: String = ""): Attr? =
            attrs.firstOrNull { it.type == type && it.name == name }

        /** 找记录内某属性的字节偏移（首个匹配 type+name）。 */
        fun attrOffsetOf(rec: ByteArray, type: Long, name: String): Int? {
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

        // ---- data runs 解码 ----

        /** 解码 runlist：变长记录，首字节高 4 位=长度字段字节数，低 4 位=偏移字段字节数。 */
        internal fun decodeRuns(rec: ByteArray, runsOff: Int): List<DataRun> {
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

        /** 编码单 run（绝对 LCN，len/off 各用最小字节数）。末尾补 0 结束符。 */
        fun encodeSingleRun(lcn: Long, length: Long): ByteArray {
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
        internal fun encodeMultiRun(runs: List<DataRun>): ByteArray {
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

        // ---- 索引项原语 ----

        /** 构建单条索引项字节。末项+无内容时 contentLen=0。 */
        fun buildIndexEntry(fnContent: ByteArray, mftRef: Long,
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
            // 子节点 VCN 必须落在 entryLen-8（与 Windows 一致）。写在 0x10+contentLen 仅当 contentLen
            //   8 字节对齐时正确；否则 Windows 读 entryLen-8 处读到 0 → B+树子节点定位失败。
            if (hasSubnode) putU64(entry, entryLen - 8, subnodeVcn)
            return entry
        }

        /** 从索引项字节提取 mftRef（低 48 位）。 */
        fun entryMftRef(entry: ByteArray): Long = u64(entry, 0) and 0x0000FFFFFFFFFFFFL

        /** 从索引项字节提取文件名（用于排序）。 */
        fun entryFileName(entry: ByteArray): String {
            val contentLen = u16(entry, 10)
            if (contentLen < 0x42) return ""
            val nameLen = entry[0x10 + 0x40].toInt() and 0xFF
            val sb = StringBuilder(nameLen)
            for (k in 0 until nameLen) sb.append(u16(entry, 0x10 + 0x42 + k * 2).toChar())
            return sb.toString()
        }

        /**
         * NTFS COLLATION_FILENAME 比较：逐 UTF-16 码元用 $UpCase 表 upcase 后无符号比较。
         * 与 [com.henglie.sealchest.fs.NtfsTables.buildUpcaseTable] 造的卷上 $UpCase 表同口径
         * （ASCII a..z→A..Z，其余 identity），保证排序键与落盘 $UpCase 一致。
         * 替代 String.compareTo(ignoreCase=true)（后者用 JVM 全 Unicode 大写映射，非 ASCII 名与 NTFS 不一致）。
         */
        fun collationCompare(a: String, b: String): Int {
            val len = minOf(a.length, b.length)
            for (i in 0 until len) {
                val ca = if (a[i] in 'a'..'z') (a[i].code - 32).toChar() else a[i]
                val cb = if (b[i] in 'a'..'z') (b[i].code - 32).toChar() else b[i]
                if (ca != cb) return ca.code - cb.code
            }
            return a.length - b.length
        }

        /** 把任意索引项（可能带子节点 VCN）剥离成纯叶子项：保留 mftRef+content，清 flags，重算 entryLen。 */
        fun stripToLeafEntry(entry: ByteArray): ByteArray {
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
        fun buildSubnodeEntry(leafEntry: ByteArray, subnodeVcn: Long): ByteArray {
            val contentLen = u16(leafEntry, 10)
            val bodyLen = 0x10 + contentLen + 8
            val entryLen = align8(bodyLen)
            val out = ByteArray(entryLen)
            System.arraycopy(leafEntry, 0, out, 0, 0x10 + contentLen)
            putU16(out, 8, entryLen)
            putU16(out, 12, INDEX_ENTRY_HAS_SUBNODE)
            // 子节点 VCN 落 entryLen-8：contentLen 非 8 对齐时 0x10+contentLen ≠ entryLen-8，
            //   Windows 读 entryLen-8 处得 0 → 子节点定位失败（大目录 B+树遍历坏）。
            putU64(out, entryLen - 8, subnodeVcn)
            return out
        }

        /** 解析一段索引项（从 [start] 起，遇 LAST 停），返回各项文件名。用于自测回解。 */
        fun parseEntryNames(buf: ByteArray, start: Int, end: Int): List<String> {
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

        // ---- $FILE_NAME body ----

        /**
         * 造「索引项用的 $FILE_NAME 内容体」（也复用作 $FILE_NAME 属性内容）。
         * 布局：parentRef(8) + 4×时间(32) + allocSize(8) + realSize(8) + flags(4) + reparse(4)
         *       + nameLen(1) + namespace(1) + name(UTF-16LE)。
         * [ns] 命名空间：合法 8.3 名传 [NS_WIN32_AND_DOS]（单项 link=1）；非 8.3 名的长名传
         *   [NS_WIN32]、其 DOS 短名传 [NS_DOS]（双项 link=2）。默认 [NS_WIN32] 仅为兼容旧调用方，
         *   新调用方应通过 [planFileNames] 规划后显式传 ns。
         */
        fun buildFileNameForIndex(mftRefUnused: Long, parentRef: Long, name: String,
                                  realSize: Long, allocSize: Long, isDir: Boolean,
                                  ns: Int = NS_WIN32): ByteArray {
            val contentLen = 0x42 + name.length * 2
            val b = ByteArray(contentLen)
            // 父引用：低 48 位记录号 + 高 16 位父记录序列号。系统记录（<16）序列号 = 记录号
            //   （rec0 例外=1），运行时新建记录（≥24）序列号=1。根目录(rec5)序列号必为 5，
            //   否则 chkdsk 校验「$FILE_NAME.parentRef 序列号 == 父目录实际序列号」失败 → 报
            //   「文件记录段检测到不正确的信息」。父记录号 = parentRef 低 48 位。
            val parentNo = parentRef and 0x0000FFFFFFFFFFFFL
            val parentSeq = if (parentNo in 1 until 16L) parentNo else 1L
            putU64(b, 0, parentNo or (parentSeq shl 48))
            val now = msToNtfsTime(System.currentTimeMillis())
            putU64(b, 0x08, now); putU64(b, 0x10, now); putU64(b, 0x18, now); putU64(b, 0x20, now)
            putU64(b, 0x28, allocSize)
            putU64(b, 0x30, realSize)
            putU32(b, 0x38, if (isDir) 0x10000000L else 0x20L)  // flags
            putU32(b, 0x3C, 0L)                                 // reparse
            b[0x40] = name.length.toByte()                      // 名字符数
            b[0x41] = ns.toByte()                               // namespace（8.3=3 / 长名=1 / DOS 短名=2）
            for (k in name.indices) putU16(b, 0x42 + k * 2, name[k].code)
            return b
        }

        // ---- DOS 8.3 短名策略 ----
        //
        // 与真实 Windows 一致：合法 8.3 名 → 单项 ns=3(link=1)；非 8.3 名 → ns=1 长名 + ns=2 生成的
        //   DOS 短名(link=2，双 $FILE_NAME、双 $I30 项)。chkdsk 阶段2 校验「ns=1 须有 ns=2 孪生、
        //   ns=3 须为合法 8.3」；旧码硬编码 ns=1 却从不生成短名 → 报「索引项不正确」+「文件名错误」。

        /** DOS 8.3 合法字符（大写字母、数字、部分符号）。小写字母不算——DOS 名一律存大写。 */
        private const val DOS_LEGAL_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#\$%&'()-@^_`{}~"

        private fun isDosLegalChar(c: Char): Boolean = DOS_LEGAL_CHARS.indexOf(c) >= 0

        /**
         * 判断 [name] 是否为合法 DOS 8.3 名（→ 单项 ns=3）：至多一个点、基名 1-8、扩展 0-3、
         * 仅大写字母/数字/允许符号。小写、多点、超长、含其他字符 → false（须生成短名）。
         */
        fun isLegalDosName(name: String): Boolean {
            if (name.isEmpty() || name.length > 12) return false
            if (name.count { it == '.' } > 1) return false
            val dot = name.lastIndexOf('.')
            val base = if (dot < 0) name else name.substring(0, dot)
            val ext = if (dot < 0) "" else name.substring(dot + 1)
            if (base.isEmpty() || base.length > 8) return false
            if (ext.length > 3) return false
            for (c in base) if (!isDosLegalChar(c)) return false
            for (c in ext) if (!isDosLegalChar(c)) return false
            return true
        }

        /**
         * 生成 DOS 8.3 短名（~N 查重）：大写化 → 按末点定 base/ext → 去非法字符 → ext 截 3 →
         * base 截到 8-len("~N") → 尾接 ~N。N 从 1 递增至不与 [existing] 冲突（大小写不敏感）。
         * [existing] 应含目录内已有 DOS 短名(ns=2)与合法 8.3 长名(ns=3)。
         */
        fun generateDosShortName(name: String, existing: Set<String>): String {
            val upper = name.uppercase()
            val dot = upper.lastIndexOf('.')
            var base = if (dot < 0) upper else upper.substring(0, dot)
            var ext = if (dot < 0) "" else upper.substring(dot + 1)
            base = base.filter { isDosLegalChar(it) }
            ext = ext.filter { isDosLegalChar(it) }
            if (base.isEmpty()) base = "_"          // 全非法字符兜底
            ext = ext.take(3)
            var n = 1
            while (n <= 999999) {
                val suffix = "~$n"
                val baseTrunc = base.take(8 - suffix.length)
                val cand = if (ext.isEmpty()) "$baseTrunc$suffix" else "$baseTrunc$suffix.$ext"
                if (existing.none { it.equals(cand, ignoreCase = true) }) return cand
                n++
            }
            return if (ext.isEmpty()) "${base.take(2)}~1" else "${base.take(2)}~1.$ext"
        }

        /**
         * 规划一个文件名应落盘的 (名, namespace) 列表：
         *   合法 8.3 名 → [(name, NS_WIN32_AND_DOS)]（单项，link=1）；
         *   非 8.3 名  → [(name, NS_WIN32), (短名, NS_DOS)]（双项，link=2）。
         * [existingShortNames] 为目录内已有 DOS 短名/合法 8.3 长名集合，用于 ~N 查重。
         */
        fun planFileNames(name: String, existingShortNames: Set<String>): List<Pair<String, Int>> =
            if (isLegalDosName(name)) listOf(name to NS_WIN32_AND_DOS)
            else listOf(name to NS_WIN32, generateDosShortName(name, existingShortNames) to NS_DOS)
    }
}
