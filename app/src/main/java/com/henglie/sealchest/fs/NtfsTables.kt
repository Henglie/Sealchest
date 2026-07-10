package com.henglie.sealchest.fs

/**
 * NTFS 造盘辅助：纯函数工具（时间戳、序列号、字节写入、data run 编码）
 * + $UpCase 大写表 + $AttrDef 属性定义表。供 [NtfsFormatter] 与 [NtfsRecords] 共用。
 *
 * 与 [NtfsFileSystem] 读侧的对应工具（[NtfsFileSystem.stampUsa]、[NtfsFileSystem.putU16]
 * 等）刻意不复用：读侧是 instance 方法、绑 [VolumeReader]，造盘侧是无状态 pure function，
 * 两端语义独立避免耦合。
 */

/** NTFS 时间基准：1601-01-01 与 1970-01-01 的毫秒差（同 [NtfsFileSystem.NTFS_EPOCH_DIFF_MS]）。 */
internal const val NTFS_EPOCH_DIFF_MS = 11644473600000L

/** MFT 引用：低 48 位 = 记录号，高 16 位 = 序列号（默认 1，与新建记录 sequence=1 对齐）。 */
internal fun mftRef(recordNo: Long): Long =
    (recordNo and 0x0000FFFFFFFFFFFFL) or (1L shl 48)

/** Unix 毫秒 → NTFS 100 纳秒单位（自 1601 起）。 */
internal fun msToNtfsTime(ms: Long): Long = (ms + NTFS_EPOCH_DIFF_MS) * 10000L

/** 32 位卷序列号（纳秒 + 毫秒混合熵，足够空盘用）。 */
internal fun randomSerial(): Long {
    val nano = System.nanoTime()
    val mix = nano xor (nano ushr 32) xor System.currentTimeMillis()
    return mix and 0xFFFFFFFFL
}

/** 小端写 u16。 */
internal fun putU16(buf: ByteArray, off: Int, v: Int) {
    buf[off] = (v and 0xFF).toByte()
    buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
}

/** 小端写 u16（Long 重载，截低 16 位）。 */
internal fun putU16(buf: ByteArray, off: Int, v: Long) = putU16(buf, off, v.toInt())

/** 小端写 u32。 */
internal fun putU32(buf: ByteArray, off: Int, v: Long) {
    buf[off] = (v and 0xFF).toByte()
    buf[off + 1] = ((v ushr 8) and 0xFF).toByte()
    buf[off + 2] = ((v ushr 16) and 0xFF).toByte()
    buf[off + 3] = ((v ushr 24) and 0xFF).toByte()
}

/** 小端写 u64。 */
internal fun putU64(buf: ByteArray, off: Int, v: Long) {
    var i = 0
    while (i < 8) {
        buf[off + i] = ((v ushr (8 * i)) and 0xFF).toByte()
        i++
    }
}

/** 8 字节对齐（属性头与属性体均须 8 对齐）。 */
internal fun align8(v: Int): Int = (v + 7) and 7.inv()

/**
 * 编码单段 data run（[length] 簇，绝对 LCN = [lcn]，相对前一段的偏移即 lcn 本身——首段场景）。
 *
 * Runlist 变长记录：首字节高 4 位 = offset 字节数，低 4 位 = length 字节数；
 * offset 字段为有符号相对偏移。返回不带终结符的字节；调用方需在末尾追加 0x00。
 *
 * 仅处理 lcn ≥ 0；稀疏段用 [encodeSparseRun]。
 */
internal fun encodeSingleRun(length: Long, lcn: Long): ByteArray {
    require(lcn >= 0L) { "encodeSingleRun 仅接受非负 LCN：$lcn（稀疏用 encodeSparseRun）" }
    val lenBytes = bytesNeededUnsigned(length)
    val offBytes = bytesNeededSignedPositive(lcn)
    val out = ByteArray(1 + lenBytes + offBytes)
    out[0] = ((offBytes shl 4) or lenBytes).toByte()
    var i = 1
    var v = length
    repeat(lenBytes) {
        out[i++] = (v and 0xFF).toByte()
        v = v ushr 8
    }
    v = lcn
    repeat(offBytes) {
        out[i++] = (v and 0xFF).toByte()
        v = v ushr 8
    }
    return out
}

/** 编码稀疏段（无 LCN，offset 字节数 = 0）。返回不带终结符的字节。 */
internal fun encodeSparseRun(length: Long): ByteArray {
    val lenBytes = bytesNeededUnsigned(length)
    val out = ByteArray(1 + lenBytes)
    out[0] = lenBytes.toByte()             // 高 4 位 = 0 表示无 offset
    var i = 1
    var v = length
    repeat(lenBytes) {
        out[i++] = (v and 0xFF).toByte()
        v = v ushr 8
    }
    return out
}

/** 无符号值需要的最少字节数。 */
private fun bytesNeededUnsigned(v: Long): Int {
    var n = 1
    var x = v ushr 8
    while (x != 0L) { n++; x = x ushr 8 }
    return n
}

/**
 * 非负值按有符号编码需要的字节数：保证最高字节的最高位为 0（否则会被读成负数）。
 * 例：0x80 需要 2 字节（0x80, 0x00），0x7F 只需 1 字节。
 */
private fun bytesNeededSignedPositive(v: Long): Int {
    if (v == 0L) return 1
    var n = 1
    var x = v ushr 8
    while (x != 0L || (v ushr ((n - 1) * 8) and 0x80L) != 0L) {
        n++
        x = x ushr 8
        if (n >= 8) return 8
    }
    return n
}

/**
 * 构造 $UpCase 表：65536 个 UTF-16LE 码点（128KB）。
 *
 * mkntfs 做法：identity + ASCII 'a'..'z' → 'A'..'Z'。Windows 挂载后会按自己的表
 * 校验，不一致则重建（对空盘无副作用）。
 */
internal fun buildUpcaseTable(): ByteArray {
    val table = ByteArray(65536 * 2)
    var off = 0
    for (i in 0 until 65536) {
        val up = if (i in 'a'.code..'z'.code) i + ('A' - 'a') else i
        putU16(table, off, up)
        off += 2
    }
    return table
}

/**
 * 构造 $AttrDef 表：16 条标准属性定义 × 160B = 2560B。
 *
 * 每条 160B 布局：
 *   0x00-0x7F  名字 UTF-16LE（128B = 64 字符，不足补 0）
 *   0x80-0x83  类型 u32
 *   0x84-0x87  显示规则 u32（0）
 *   0x88-0x8B  排序规则 u32（$FILE_NAME=1 FILENAME，$DATA=2，其余 0）
 *   0x8C-0x8F  标志 u32（0=可驻留可非驻留）
 *   0x90-0x97  最小长度 s64
 *   0x98-0x9F  最大长度 s64（-1 = 不限）
 */
internal fun buildAttrDefTable(): ByteArray {
    // (名字, 类型, 最小长度)
    val defs = listOf(
        Triple("\$STANDARD_INFORMATION", 0x10L, 0x48L),
        Triple("\$ATTRIBUTE_LIST", 0x20L, 0x20L),
        Triple("\$FILE_NAME", 0x30L, 0x44L),
        Triple("\$OBJECT_ID", 0x40L, 0x10L),
        Triple("\$SECURITY_DESCRIPTOR", 0x50L, 0x00L),
        Triple("\$VOLUME_NAME", 0x60L, 0x00L),
        Triple("\$VOLUME_INFORMATION", 0x70L, 0x0CL),
        Triple("\$DATA", 0x80L, 0x00L),
        Triple("\$INDEX_ROOT", 0x90L, 0x01L),
        Triple("\$INDEX_ALLOCATION", 0xA0L, 0x00L),
        Triple("\$BITMAP", 0xB0L, 0x00L),
        Triple("\$REPARSE_POINT", 0xC0L, 0x00L),
        Triple("\$EA_INFORMATION", 0xD0L, 0x08L),
        Triple("\$EA", 0xE0L, 0x00L),
        Triple("\$PROPERTY_SET", 0xF0L, 0x00L),
        Triple("\$LOGGED_UTILITY_STREAM", 0x100L, 0x00L),
    )
    val table = ByteArray(16 * 160)
    var off = 0
    for ((name, type, minSize) in defs) {
        val nameBytes = name.toByteArray(Charsets.UTF_16LE)
        System.arraycopy(nameBytes, 0, table, off, nameBytes.size)
        putU32(table, off + 0x80, type)
        putU32(table, off + 0x84, 0L)
        if (type == 0x30L) putU32(table, off + 0x88, 1L) else putU32(table, off + 0x88, 0L)
        putU32(table, off + 0x8C, 0L)
        putU64(table, off + 0x90, minSize)
        putU64(table, off + 0x98, -1L)
        off += 160
    }
    return table
}
