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
        // 0x16 resident_flags：$FILE_NAME(0x30) 恒被 $I30 索引 → RESIDENT_ATTR_IS_INDEXED=0x01
        //   （真·Windows/mkntfs 都置此位）。漏置 → chkdsk 判每条 $FILE_NAME「属性记录损坏」。
        val residentFlags = if (type == NtfsFormatter.ATTR_FILE_NAME) 0x01 else 0x00
        putU16(buf, s + 0x14, valOff); putU16(buf, s + 0x16, residentFlags)
        if (nameLen > 0) System.arraycopy(nameBytes, 0, buf, s + 0x18, nameBytes.size)
        System.arraycopy(content, 0, buf, s + valOff, content.size)
        val id = nextAttrId++; pos += totalLen; return id
    }

    fun nonResident(
        type: Long, startVcn: Long, endVcn: Long, runs: ByteArray,
        realSize: Long, name: String = "",
        allocOverride: Long? = null, initOverride: Long? = null,
        sparse: Boolean = false,
    ): Int {
        val nameBytes = if (name.isNotEmpty()) name.toByteArray(Charsets.UTF_16LE) else ByteArray(0)
        val nameLen = nameBytes.size / 2
        // 稀疏/压缩非驻留头多一个 compressed_size(u64@0x40)，故固定头 0x48 而非 0x40，
        //   name/runs 相应后移（ntfs-3g attrib.h：该字段仅当 COMPRESSED|SPARSE 存在）。
        val headerEnd = if (sparse) 0x48 else 0x40
        val nameOff = if (nameLen > 0) headerEnd else 0
        val runsOff = align8(headerEnd + nameLen * 2)
        val totalLen = align8(runsOff + runs.size)
        val allocSize = allocOverride ?: (endVcn - startVcn + 1) * bytesPerCluster
        val initSize = initOverride ?: realSize
        val s = pos
        putU32(buf, s, type); putU32(buf, s + 4, totalLen.toLong())
        buf[s + 8] = 1; buf[s + 9] = nameLen.toByte()
        putU16(buf, s + 0x0A, nameOff)
        putU16(buf, s + 0x0C, if (sparse) 0x8000 else 0)   // ATTR_IS_SPARSE
        putU16(buf, s + 0x0E, nextAttrId)
        putU64(buf, s + 0x10, startVcn); putU64(buf, s + 0x18, endVcn)
        putU16(buf, s + 0x20, runsOff); putU16(buf, s + 0x22, 0)
        putU32(buf, s + 0x24, 0)
        putU64(buf, s + 0x28, allocSize); putU64(buf, s + 0x30, realSize); putU64(buf, s + 0x38, initSize)
        // 稀疏：compressed_size(0x40) = 实际已分配字节（满卷全稀疏 = 0 = allocSize）。
        if (sparse) putU64(buf, s + 0x40, allocSize)
        if (nameLen > 0) System.arraycopy(nameBytes, 0, buf, s + nameOff, nameBytes.size)
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
    putU32(b, 0x20, if (isDir) NtfsFormatter.FILE_ATTR_SYSTEM or NtfsFormatter.FILE_ATTR_I30_INDEX_PRESENT
                    else NtfsFormatter.FILE_ATTR_SYSTEM)
    // security_id 在内容偏移 0x34（72 字节 NTFS 3.x 版 $STANDARD_INFORMATION）。指向 $Secure
    //   共享描述符 0x100，使每个文件/目录都有可解析的安全描述符 → 手动 chkdsk 不报「缺失安全描述符」。
    //   owner_id(0x30)/quota(0x38)/usn(0x40) 留 0（空盘无配额、无 USN 日志）。
    putU32(b, 0x34, NtfsSecure.FIRST_SECURITY_ID.toLong())
    return b
}

/**
 * $FILE_NAME 内容体。[allocSize]=簇对齐分配大小(0x28)、[realSize]=真实字节(0x30)——
 *   mkntfs 对带 $DATA 的系统文件填真实 alloc/real，chkdsk 校验此缓存尺寸；旧码全填 0
 *   → 记录 0($MFT) 等被 chkdsk 纠正。目录无 $DATA，两者留 0。
 * [isDir]=true 时 file_attributes(0x38) 置目录位 0x10000000(I30_INDEX_PRESENT)——否则记录头
 *   FLAG_DIRECTORY 与 $FILE_NAME 说法矛盾，chkdsk 报「文件属性不一致」并重写。
 */
internal fun buildFileNameContent(
    parentRef: Long, name: String, now: Long,
    ns: Int = NtfsRecordCodec.NS_WIN32_AND_DOS,
    allocSize: Long = 0L, realSize: Long = 0L, isDir: Boolean = false,
): ByteArray {
    val nameUtf16 = name.toByteArray(Charsets.UTF_16LE)
    val nameChars = nameUtf16.size / 2
    val b = ByteArray(0x42 + nameChars * 2)
    putU64(b, 0x00, parentRef)
    putU64(b, 0x08, now); putU64(b, 0x10, now); putU64(b, 0x18, now); putU64(b, 0x20, now)
    putU64(b, 0x28, allocSize); putU64(b, 0x30, realSize)
    putU32(b, 0x38, if (isDir) NtfsFormatter.FILE_ATTR_SYSTEM or NtfsFormatter.FILE_ATTR_I30_INDEX_PRESENT
                    else NtfsFormatter.FILE_ATTR_SYSTEM)
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
    // index block size = max(4096, 簇)（mkntfs：索引块绝不小于一簇）。0x0C 按簇编码
    //   （与 boot[0x44] 同一 ClustersPerIndexBuffer 编码）。大簇下 0x08 须随簇变（旧写死 4096
    //   与 boot 解析出的簇大小矛盾 → chkdsk 报索引块尺寸不符 / 运行时多叶构建被拒）。
    putU32(b, 0x08, NtfsFormatter.indexRecordSize(bytesPerCluster).toLong())
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
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(mftRef(5L), "\$MFT", now,
        allocSize = mftClusters * bpc.toLong(), realSize = mftClusters * bpc.toLong()))
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
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$MFTMirr", now,
        allocSize = mirrClusters * bpc.toLong(), realSize = mirrClusters * bpc.toLong()))
    val runs = encodeSingleRun(mirrClusters, mirrLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, mirrClusters - 1, runs, mirrClusters * bpc.toLong())
    return rb.end()
}

internal fun buildLogFileRecord(logLcn: Long, logClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$LogFile", now,
        allocSize = logClusters * bpc.toLong(), realSize = logClusters * bpc.toLong()))
    val runs = encodeSingleRun(logClusters, logLcn) + byteArrayOf(0)
    // initSize=0：$LogFile 数据是 0xFF 填充（非有效 RSTR restart page），initSize=0 表示
    //   「数据未初始化」→ chkdsk 不尝试解析 restart page，接受为空日志。原来 initSize=realSize
    //   >0 让 chkdsk 认为 $LogFile 已初始化 → 读取首扇区找 'RSTR' 签名遇 0xFF → 报「属性
    //   记录(0x80)损坏」。ntfs-3g mkntfs 写真实 restart pages 时 initSize=realSize；只填 0xFF
    //   时 initSize=0。16k/64k 簇阶段1中止的根因。
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, logClusters - 1, runs, logClusters * bpc.toLong(),
        initOverride = 0L)
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
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$AttrDef", now,
        allocSize = attrDefClusters * bpc.toLong(), realSize = NtfsFormatter.ATTRDEF_SIZE.toLong()))
    val runs = encodeSingleRun(attrDefClusters, attrDefLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, attrDefClusters - 1, runs, NtfsFormatter.ATTRDEF_SIZE.toLong())
    return rb.end()
}

internal fun buildRootDirRecord(now: Long, rootRef: Long, bpc: Int): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now, isDir = true))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, ".", now, ns = 3, isDir = true))
    // 目录索引属性必须名 "$I30"（真实 NTFS 规范：文件名索引属性统一命名 $I30）。运行时写路径
    //   insertIndexEntry 硬性 findAttr(INDEX_ROOT,"$I30")、无兜底——根目录 $INDEX_ROOT 无名则
    //   每次写根目录（建文件/建子目录）insertIndexEntry 恒返回 false → 全部写操作失败。
    //   读侧 listDirEntries 有 firstOrNull{type==INDEX_ROOT} 兜底故能读，掩盖了此 bug。
    //   与 buildExtendRecord（Bug8 已修）对齐。
    rb.resident(NtfsFormatter.ATTR_INDEX_ROOT, buildIndexRootEmpty(bpc), name = "\$I30")
    rb.flags(NtfsFormatter.FLAG_IN_USE or NtfsFormatter.FLAG_DIRECTORY)
    return rb.end()
}

internal fun buildBitmapRecord(bitmapLcn: Long, bitmapClusters: Long, bpc: Int, bitmapBytes: Long, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Bitmap", now,
        allocSize = bitmapClusters * bpc.toLong(), realSize = bitmapBytes))
    val runs = encodeSingleRun(bitmapClusters, bitmapLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, bitmapClusters - 1, runs, bitmapBytes)
    return rb.end()
}

internal fun buildBootFileRecord(bootLcn: Long, bootClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Boot", now,
        allocSize = bootClusters * bpc.toLong(), realSize = NtfsFormatter.BOOT_SIZE.toLong()))
    val runs = encodeSingleRun(bootClusters, bootLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, bootClusters - 1, runs, NtfsFormatter.BOOT_SIZE.toLong())
    return rb.end()
}

internal fun buildBadClusRecord(totalClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$BadClus", now))
    // 真实 NTFS $BadClus 布局：空的无名 $DATA（坏簇表本体在 $Bad）+ 命名流 "$Bad" 覆盖满卷。
    //   逐字节对比真·Windows 格式化盘：$Bad 用单个 hole run 覆盖满卷，但属性头 flags=0
    //   （不标 SPARSE 0x8000）、无 compressed_size 字段、alloc=real=满卷字节、init=0。
    //   旧码标 sparse=true + allocOverride=0 → 属性头带 SPARSE 位 + compressed_size + alloc=0，
    //   与真·Windows 不符 → chkdsk 报「记录 8 属性(80,$Bad)损坏」。
    //   属性同 type(0x80) 按名序：无名 "" < "$Bad"。
    rb.resident(NtfsFormatter.ATTR_DATA, ByteArray(0))
    val badRuns = encodeSparseRun(totalClusters) + byteArrayOf(0)
    rb.nonResident(
        NtfsFormatter.ATTR_DATA, 0L, totalClusters - 1, badRuns,
        realSize = totalClusters * bpc.toLong(), name = "\$Bad",
        initOverride = 0L, sparse = false,
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
    // $Secure 用 $SDH/$SII 视图索引（非 $I30 目录）→ flags = IN_USE|IS_VIEW_INDEX(0x09)，
    //   与真·Windows 一致。仅 IN_USE(0x01) → chkdsk 报「Flags for file record segment 9 are incorrect」。
    rb.flags(NtfsFormatter.FLAG_IN_USE or NtfsFormatter.FLAG_IS_VIEW_INDEX)
    return rb.end()
}

internal fun buildUpcaseFileRecord(upcaseLcn: Long, upcaseClusters: Long, bpc: Int, now: Long, rootRef: Long): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$UpCase", now,
        allocSize = upcaseClusters * bpc.toLong(), realSize = NtfsFormatter.UPCASE_SIZE.toLong()))
    val runs = encodeSingleRun(upcaseClusters, upcaseLcn) + byteArrayOf(0)
    rb.nonResident(NtfsFormatter.ATTR_DATA, 0L, upcaseClusters - 1, runs, NtfsFormatter.UPCASE_SIZE.toLong())
    return rb.end()
}

internal fun buildExtendRecord(now: Long, rootRef: Long, bpc: Int): ByteArray {
    val rb = RecBuilder(bpc)
    rb.resident(NtfsFormatter.ATTR_STANDARD_INFO, buildStdInfo(now, isDir = true))
    rb.resident(NtfsFormatter.ATTR_FILE_NAME, buildFileNameContent(rootRef, "\$Extend", now, isDir = true))
    // Bug8：目录索引属性必须名 "$I30"（读侧 findAttr(INDEX_ROOT,"$I30")、chkdsk 均按此名找），旧码无名。
    rb.resident(NtfsFormatter.ATTR_INDEX_ROOT, buildIndexRootEmpty(bpc), name = "\$I30")
    rb.flags(NtfsFormatter.FLAG_IN_USE or NtfsFormatter.FLAG_DIRECTORY)
    return rb.end()
}
