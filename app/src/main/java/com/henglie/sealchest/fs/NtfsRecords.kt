package com.henglie.sealchest.fs

/**
 * NTFS 造盘：MFT 记录构造（[RecBuilder] + 12 条元数据记录 0..11）。
 *
 * 由 [NtfsFormatter.buildEmpty] 调用，产出 1024B FILE 记录（已 USA stamp）。
 * 底层工具（[putU16] 等）见 [NtfsTables]，常量见 [NtfsFormatter]。
 */

internal class RecBuilder(private val bytesPerCluster: Int) {
    val buf = ByteArray(NtfsFormatter.MFT_RECORD_SIZE)
    private var pos = 0x38
    private var nextAttrId = 0
    private var flags = NtfsFormatter.FLAG_IN_USE

    init {
        buf[0] = 'F'.code.toByte(); buf[1] = 'I'.code.toByte()
        buf[2] = 'L'.code.toByte(); buf[3] = 'E'.code.toByte()
        putU16(buf, 0x04, 0x30)
        putU16(buf, 0x06, 1 + NtfsFormatter.MFT_RECORD_SIZE / NtfsFormatter.SECTOR)
        putU64(buf, 0x08, 0L)
        putU16(buf, 0x10, 1)
        putU16(buf, 0x12, 1)
        putU16(buf, 0x14, 0x38)
        putU32(buf, 0x18, 0x38)
        putU32(buf, 0x1C, NtfsFormatter.MFT_RECORD_SIZE.toLong())
        putU64(buf, 0x20, 0L)
        putU16(buf, 0x28, 0)
        putU16(buf, 0x30, 1)
    }

    fun flags(f: Int): RecBuilder { flags = f; return this }
    fun hardLinks(n: Int): RecBuilder { putU16(buf, 0x12, n); return this }

    fun resident(type: Long, content: ByteArray, name: String = ""): Int {
        val nameBytes = if (name.isNotEmpty()) name.toByteArray(Charsets.UTF_16LE) else ByteArray(0)
        val nameLen = nameBytes.size / 2
        val valOff = align8(0x18 + nameLen * 2)
        val totalLen = align8(valOff + content.size)
        val s = pos
        putU32(buf, s, type); putU32(buf, s + 4, totalLen.toLong())
        buf[s + 8] = 0; buf[s + 9] = nameLen.toByte()
        putU16(buf, s + 0x0A, if (nameLen > 0) 0x18 else 0)
        putU16(buf, s + 0x0C, 0); putU16(buf, s + 0x0E, nextAttrId)
        putU32(buf, s + 0x10, content.size.toLong())
        putU16(buf, s + 0x14, valOff); putU16(buf, s + 0x16, 0)
        if (nameLen > 0) System.arraycopy(nameBytes, 0, buf, s + 0x18, nameBytes.size)
        System.arraycopy(content, 0, buf, s + valOff, content.size)
        val id = nextAttrId++; pos += totalLen; return id
    }

    fun nonResident(
        type: Long, startVcn: Long, endVcn: Long, runs: ByteArray,
        realSize: Long, name: String = "",
        allocOverride: Long? = null, initOverride: Long? = null,
    ): Int {
        val nameBytes = if (name.isNotEmpty()) name.toByteArray(Charsets.UTF_16LE) else ByteArray(0)
        val nameLen = nameBytes.size / 2
        val runsOff = align8(0x40 + nameLen * 2)
        val totalLen = align8(runsOff + runs.size)
        val allocSize = allocOverride ?: (endVcn - startVcn + 1) * bytesPerCluster
        val initSize = initOverride ?: realSize
        val s = pos
        putU32(buf, s, type); putU32(buf, s + 4, totalLen.toLong())
        buf[s + 8] = 1; buf[s + 9] = nameLen.toByte()
        putU16(buf, s + 0x0A, if (nameLen > 0) 0x40 else 0)
        putU16(buf, s + 0x0C, 0); putU16(buf, s + 0x0E, nextAttrId)
        putU64(buf, s + 0x10, startVcn); putU64(buf, s + 0x18, endVcn)
        putU16(buf, s + 0x20, runsOff); putU16(buf, s + 0x22, 0)
        putU32(buf, s + 0x24, 0)
        putU64(buf, s + 0x28, allocSize); putU64(buf, s + 0x30, realSize); putU64(buf, s + 0x38, initSize)
        if (nameLen > 0) System.arraycopy(nameBytes, 0, buf, s + 0x40, nameBytes.size)
        System.arraycopy(runs, 0, buf, s + runsOff, runs.size)
        val id = nextAttrId++; pos += totalLen; return id
    }

    fun end(): ByteArray {
        putU32(buf, pos, NtfsFormatter.ATTR_END); putU32(buf, pos + 4, 8)
        pos += 8
        putU32(buf, 0x18, pos.toLong())
        putU16(buf, 0x28, nextAttrId)
        putU16(buf, 0x16, flags)
        stampUsa(buf)
        return buf
    }
}

internal fun stampUsa(buf: ByteArray) {
    val usaOff = readU16(buf, 4)
    val usaCount = readU16(buf, 6)
    if (usaCount < 2) return
    val usn = 1
    buf[usaOff] = (usn and 0xFF).toByte()
    buf[usaOff + 1] = ((usn ushr 8) and 0xFF).toByte()
    for (i in 1 until usaCount) {
        val end = i * NtfsFormatter.SECTOR - 2
        if (end + 2 > buf.size) break
        val orig = readU16(buf, end)
        buf[usaOff + i * 2] = (orig and 0xFF).toByte()
        buf[usaOff + i * 2 + 1] = ((orig ushr 8) and 0xFF).toByte()
        buf[end] = (usn and 0xFF).toByte()
        buf[end + 1] = ((usn ushr 8) and 0xFF).toByte()
    }
}

private fun readU16(buf: ByteArray, off: Int): Int =
    (buf[off].toInt() and 0xFF) or ((buf[off + 1].toInt() and 0xFF) shl 8)

internal fun buildStdInfo(now: Long, isDir: Boolean = false): ByteArray {
    val b = ByteArray(72)
    putU64(b, 0x00, now); putU64(b, 0x08, now); putU64(b, 0x10, now); putU64(b, 0x18, now)
    putU32(b, 0x20, if (isDir) NtfsFormatter.FILE_ATTR_DIR_SYSTEM else NtfsFormatter.FILE_ATTR_SYSTEM)
    // security_id 在内容偏移 0x34（72 字节 NTFS 3.x 版 $STANDARD_INFORMATION）。指向 $Secure
    //   共享描述符 0x100，使每个文件/目录都有可解析的安全描述符 → 手动 chkdsk 不报「缺失安全描述符」。
    //   owner_id(0x30)/quota(0x38)/usn(0x40) 留 0（空盘无配额、无 USN 日志）。
    putU32(b, 0x34, NtfsSecure.FIRST_SECURITY_ID.toLong())
    return b
}

internal fun buildFileNameContent(
    parentRef: Long, name: String, now: Long,
    ns: Int = NtfsFormatter.NS_WIN32_AND_DOS, fileSize: Long = 0L,
): ByteArray {
    val nameUtf16 = name.toByteArray(Charsets.UTF_16LE)
    val nameChars = nameUtf16.size / 2
    val b = ByteArray(0x42 + nameChars * 2)
    putU64(b, 0x00, parentRef)
    putU64(b, 0x08, now); putU64(b, 0x10, now); putU64(b, 0x18, now); putU64(b, 0x20, now)
    putU64(b, 0x28, fileSize); putU64(b, 0x30, fileSize)
    putU32(b, 0x38, NtfsFormatter.FILE_ATTR_SYSTEM)
    putU32(b, 0x3C, 0L)
    b[0x40] = nameChars.toByte(); b[0x41] = ns.toByte()
    System.arraycopy(nameUtf16, 0, b, 0x42, nameUtf16.size)
    return b
}

internal fun buildVolumeInfoContent(): ByteArray {
    val b = ByteArray(12)
    b[0x08] = 3; b[0x09] = 1
    // flags=0：卷出生即 clean。空盘 = 0xFF $LogFile（空日志）+ dirty=0，与 ntfs-3g mkfs 产物
    //   一致 → Windows 挂载不触发 chkdsk（兑现「别 chkdsk」）。原来出生即 dirty=1 → 每次挂载必跑
    //   chkdsk。写操作期间由 markVolumeDirty 置脏、事务成功落盘后 clearVolumeDirty 复位。
    putU16(b, 0x0A, 0x0000L)
    return b
}

internal fun buildIndexRootEmpty(bytesPerCluster: Int): ByteArray {
    // 空叶根：INDEX_ROOT 头(0x10) + INDEX_HEADER(0x10) + END 项(0x10) = 0x30。
    // BUG 修（2026-07-10）：原 END 项写 0x18（大索引带子节点的尺寸），但空根 flags=0(small 无
    //   INDEX_ALLOCATION)、END 项无 HAS_SUBNODE → 依 mkntfs 应为 0x10（sizeof INDEX_ENTRY_HEADER，
    //   无 VCN）。0x18 自相矛盾（声明有子节点空间却无子节点标志）→ chkdsk 报索引项越界/长度不符。
    //   同步 index_length/allocated 0x28→0x20，与运行时 writeEmptyIndexRootAttr 一致。
    val b = ByteArray(0x30)
    putU32(b, 0x00, NtfsFormatter.ATTR_FILE_NAME)          // indexed attr type
    putU32(b, 0x04, 1L)                                    // collation rule = COLLATION_FILENAME
    // H4：index block size 恒为 INDEX_RECORD_SIZE(4096)，不随簇大小变；0x0C 按簇编码
    //   （与 boot[0x44] 同一 ClustersPerIndexBuffer 编码）。原来两处都错填 bytesPerCluster/1。
    putU32(b, 0x08, NtfsFormatter.INDEX_RECORD_SIZE.toLong())
    b[0x0C] = NtfsFormatter.indexBufferCode(bytesPerCluster).toByte()
    putU32(b, 0x10, 0x10L)                                 // node header: entries offset（相对 INDEX_HEADER）
    putU32(b, 0x14, 0x20L)                                 // node header: index length = 头0x10 + END项0x10
    putU32(b, 0x18, 0x20L)                                 // node header: allocated size = 同上（resident 无余量）
    putU32(b, 0x1C, 0L)                                    // node header: flags = 0(small, 无 INDEX_ALLOCATION)
    putU64(b, 0x20, 0L)                                    // end entry: mftRef = 0
    putU16(b, 0x28, 0x10)                                  // end entry: entry length = 0x10（叶末项，无子节点）
    putU16(b, 0x2A, 0)                                     // end entry: content length
    putU16(b, 0x2C, NtfsFormatter.INDEX_ENTRY_LAST.toLong())  // end entry: flags = LAST
    return b
}

internal fun buildMftRecord(
    mftLcn: Long, mftClusters: Long, bpc: Int, now: Long,
    mftBitmapLcn: Long, mftBitmapClusters: Long, mftBitmapRealSize: Long,
): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(mftRef(5L), "\$MFT", now))
    val runs = encodeSingleRun(mftClusters, mftLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, mftClusters - 1, runs, mftClusters * bpc.toLong())
    // H2：$MFT 记录 0 必须带 $BITMAP(0xB0)——ensureMftBitmap 靠它定位 MFT 记录分配位图；
    //   缺失 → 找不到返 0xFF(全已用) → allocMftRecord 永远 -1 → 写文件永远失败 + chkdsk 报结构不完整。
    //   做成 nonResident（占独立簇）：writeMftBitmapByte 对 resident 直接 return 不落盘，
    //   resident 会导致分配位不持久化、重复分配（比永远失败更危险）。属性按 type 升序：0x10<0x30<0x80<0xB0。
    val bmpRuns = encodeSingleRun(mftBitmapClusters, mftBitmapLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_BITMAP, 0L, mftBitmapClusters - 1, bmpRuns, mftBitmapRealSize)
    return rb.end()
}

internal fun buildMftMirrRecord(mirrLcn: Long, mirrClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$MFTMirr", now))
    val runs = encodeSingleRun(mirrClusters, mirrLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, mirrClusters - 1, runs, mirrClusters * bpc.toLong())
    return rb.end()
}

internal fun buildLogFileRecord(logLcn: Long, logClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$LogFile", now))
    val runs = encodeSingleRun(logClusters, logLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, logClusters - 1, runs, logClusters * bpc.toLong())
    return rb.end()
}

internal fun buildVolumeRecord(volumeLabel: String, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(4096)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Volume", now))
    val labelBytes = if (volumeLabel.isNotEmpty()) volumeLabel.toByteArray(Charsets.UTF_16LE) else ByteArray(0)
    rb.resident(NtfsFormatter.ATTR_VOLUME_NAME, labelBytes)
    rb.resident(NtfsFormatter.ATTR_VOLUME_INFO, buildVolumeInfoContent())
    return rb.end()
}

internal fun buildAttrDefRecord(attrDefLcn: Long, attrDefClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$AttrDef", now))
    val runs = encodeSingleRun(attrDefClusters, attrDefLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, attrDefClusters - 1, runs, NtfsFormatter.ATTRDEF_SIZE.toLong())
    return rb.end()
}

internal fun buildRootDirRecord(now: Long, rootRef: Long, bpc: Int): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now, isDir = true))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, ".", now, ns = 3))
    rb.resident(NtfsFormatter.ATTR_INDEX_ROOT, buildIndexRootEmpty(bpc))
    rb.flags(NtfsFormatter.FLAG_IN_USE or NtfsFormatter.FLAG_DIRECTORY)
    return rb.end()
}

internal fun buildBitmapRecord(bitmapLcn: Long, bitmapClusters: Long, bpc: Int, bitmapBytes: Long, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Bitmap", now))
    val runs = encodeSingleRun(bitmapClusters, bitmapLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, bitmapClusters - 1, runs, bitmapBytes)
    return rb.end()
}

internal fun buildBootFileRecord(bootLcn: Long, bootClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Boot", now))
    val runs = encodeSingleRun(bootClusters, bootLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, bootClusters - 1, runs, NtfsFormatter.BOOT_SIZE.toLong())
    return rb.end()
}

internal fun buildBadClusRecord(totalClusters: Long, bpc: Int, volumeSizeBytes: Long, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$BadClus", now))
    val runs = encodeSparseRun(totalClusters) + byteArrayOf(0)
    rb.nonResident(
        NtfsFormatter.ATTR_DATA, 0L, totalClusters - 1, runs,
        realSize = volumeSizeBytes, allocOverride = 0L, initOverride = 0L,
    )
    return rb.end()
}

/**
 * $Secure（记录 9）：安全描述符仓库。原为空壳（无 $SDS/$SDH/$SII，所有文件 security_id=0，
 * 手动 chkdsk 会逐文件补 ACL）。现按 ntfs-3g/mkntfs 规范建最小可用体：单个共享 SD
 * （security_id=0x100，Everyone:FullControl），$SDS 数据流（主副本@0 + 镜像@0x40000）+
 * $SDH/$SII 视图索引各一项。每个文件/目录的 $STANDARD_INFORMATION.security_id 都指 0x100
 * → 手动 chkdsk 对安全项静默。
 *
 * $Secure 非 $I30 目录（用 $SDH/$SII 视图索引，不用文件名索引）→ 不置 FLAG_DIRECTORY，
 * 与真实 NTFS 一致。属性按 type 升序、同 type 按名序：
 *   $STD(0x10) < $FILE_NAME(0x30) < $DATA"$SDS"(0x80) < $INDEX_ROOT"$SDH" < $INDEX_ROOT"$SII"(0x90)。
 * $SDH/$SII 各仅一项，驻留 $INDEX_ROOT 足够，无需 $INDEX_ALLOCATION/$BITMAP。
 */
internal fun buildSecureRecord(
    now: Long, rootRef: Long, bytesPerCluster: Int,
    sdsLcn: Long, sdsClusters: Long, sd: ByteArray, hash: Int,
): ByteArray {
    val rb = RecBuilder(bytesPerCluster)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Secure", now))
    // $DATA 命名流 "$SDS"（非驻留，指向分配的簇）。realSize = 镜像跨距 + 一条对齐项。
    val sdsRuns = encodeSingleRun(sdsClusters, sdsLcn) + byteArrayOf(0)
    rb.nonResident(
        NtfsFormatter.ATTR_DATA, 0L, sdsClusters - 1, sdsRuns,
        NtfsSecure.sdsDataSize(sd), name = "\$SDS",
    )
    // $INDEX_ROOT 命名视图索引 "$SDH"（hash,id）与 "$SII"（id），各一项 + END，驻留。
    val secId = NtfsSecure.FIRST_SECURITY_ID
    rb.resident(NtfsFormatter.ATTR_INDEX_ROOT,
        NtfsSecure.buildSdhIndexRoot(secId, hash, sd.size, bytesPerCluster), name = "\$SDH")
    rb.resident(NtfsFormatter.ATTR_INDEX_ROOT,
        NtfsSecure.buildSiiIndexRoot(secId, hash, sd.size, bytesPerCluster), name = "\$SII")
    rb.flags(NtfsFormatter.FLAG_IN_USE)
    return rb.end()
}

internal fun buildUpcaseFileRecord(upcaseLcn: Long, upcaseClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$UpCase", now))
    val runs = encodeSingleRun(upcaseClusters, upcaseLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, upcaseClusters - 1, runs, NtfsFormatter.UPCASE_SIZE.toLong())
    return rb.end()
}

internal fun buildExtendRecord(now: Long, rootRef: Long, bpc: Int): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now, isDir = true))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Extend", now))
    rb.resident(NtfsFormatter.ATTR_INDEX_ROOT, buildIndexRootEmpty(bpc))
    rb.flags(NtfsFormatter.FLAG_IN_USE or NtfsFormatter.FLAG_DIRECTORY)
    return rb.end()
}
