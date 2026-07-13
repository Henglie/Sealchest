package com.henglie.sealchest.fs

/**
 * NTFS 文件系统解析层（读 + 受限写，见各方法）。
 *
 * 全部经 [VolumeReader]（解密 + 逻辑寻址），本层只见「卷内逻辑偏移」，不碰加密。
 * 与 FAT / exFAT 走同一套 [VolumeFs] 接口，[MountManager] / SAF / UI 零感知底层。
 *
 * 本类是薄壳：仅持四个模块引用 + 转发 [VolumeFs] 调用。实际逻辑在：
 *   [NtfsRecordCodec] —— 无状态工具（字节/时间/USA/属性/data run/索引项原语）
 *   [NtfsMftManager]  —— $MFT 读写、$Bitmap/$MFTMirr 定位、簇/MFT 记录位图（独占 7 个 var 状态）
 *   [NtfsIndex]       —— 目录索引读侧遍历、写侧 B+树整树重建、INDX 叶子构造、属性序列化
 *   [NtfsDataOps]     —— 文件读/写/删、目录创建/删除/重命名/移动、卷标读取
 *
 * 依赖方向（单向无环）：RecordCodec ← MftManager ← Index ← DataOps ← FileSystem。
 *
 * 写操作采用 dirty-first 策略：动盘前先 markVolumeDirty，确保中途崩溃 Windows 必触发 chkdsk。
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

    // ---- 四模块（依赖链：codec → mftMgr → index → dataOps）----
    private val codec = NtfsRecordCodec(boot)
    private val mftMgr = NtfsMftManager(reader, boot, codec)
    private val index = NtfsIndex(mftMgr, codec, reader, boot)
    private val dataOps = NtfsDataOps(mftMgr, index, codec, reader, boot)

    companion object {
        fun mount(reader: VolumeReader): NtfsFileSystem {
            val boot = NtfsBoot.parse(reader.read(0, 512))
            val fs = NtfsFileSystem(reader, boot)
            fs.mftMgr.bootstrapMft()
            fs.volumeLabel = fs.dataOps.readVolumeLabel()
            return fs
        }
    }

    // ================= VolumeFs 接口（转发到 index / dataOps）=================

    override fun listRoot(): List<FsEntry> =
        index.listDirEntries(NtfsRecordCodec.MFT_ROOT_DIR)

    override fun listDir(firstCluster: Long): List<FsEntry> =
        index.listDirEntries(if (firstCluster < 16) NtfsRecordCodec.MFT_ROOT_DIR else firstCluster)

    override fun readFile(firstCluster: Long, fileSize: Long, start: Long, length: Int): ByteArray {
        if (firstCluster < 16) return ByteArray(0)
        return dataOps.readData(firstCluster, start, length)
    }

    override fun usedDataAreaUpperBound(): Long {
        // NTFS 元数据分散、无简单位图上界。隐藏卷寄生 NTFS 外层极少见，保守返回全区。
        return boot.totalSectors * boot.bytesPerSector
    }

    // ---- 写（dirty-first：动盘前先置脏，中途被杀→Windows 触发 chkdsk）----

    override fun writeFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        mftMgr.markVolumeDirty()
        return dataOps.ntfsWriteFile(
            if (dirFirstCluster < 16) NtfsRecordCodec.MFT_ROOT_DIR else dirFirstCluster, name, bytes
        )
    }

    override fun overwriteFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean {
        val dir = if (dirFirstCluster < 16) NtfsRecordCodec.MFT_ROOT_DIR else dirFirstCluster
        mftMgr.markVolumeDirty()
        // 崩溃/写失败安全（修 H1）：不再「先删后写」——近满容器写新失败会连旧数据一并丢。
        // 改为「先以临时名写新 → 成功后删旧 → 改名回目标名」。任一步失败旧文件始终完好。
        // 临时名 = ".sctmp~"+纳秒戳，再补 '0' 到不短于目标名（≤255）。这样末步 rename 是
        // tmp→name 的「收缩」（delta≤0），rewriteFileNameAttr 必然放得下、不涉新簇分配 →
        // 末步不会因空间失败。tmp 与 name 等长，故 name 能放下则 tmp 写入也能放下。
        var tmp = ".sctmp~" + java.lang.Long.toHexString(System.nanoTime())
        while (tmp.length < name.length && tmp.length < 255) tmp += "0"
        if (tmp.length > 255) tmp = tmp.substring(0, 255)
        if (!dataOps.ntfsWriteFile(dir, tmp, bytes)) return false
        val existed = dataOps.listDirEntriesWithRef(dir).any { it.second == name }
        if (existed && !dataOps.ntfsDeleteFile(dir, name)) {
            // 删旧失败：回滚临时文件，旧文件保持原样。
            dataOps.ntfsDeleteFile(dir, tmp)
            return false
        }
        // 改名回目标名。失败时数据仍存于 tmp 名下（未丢），仅对外名不对。
        return dataOps.ntfsRename(dir, tmp, name)
    }

    override fun deleteFile(dirFirstCluster: Long, name: String): Boolean {
        mftMgr.markVolumeDirty()
        return dataOps.ntfsDeleteFile(
            if (dirFirstCluster < 16) NtfsRecordCodec.MFT_ROOT_DIR else dirFirstCluster, name
        )
    }

    override fun invalidateFsInfo() { /* NTFS 无 FAT32 FSInfo；崩溃一致性靠 chkdsk */ }

    /**
     * 写事务整体成功落盘后清 $Volume dirty 位（见 [NtfsMftManager.clearVolumeDirty]）。
     * 由 [MountManager.withWritableFs] 在 block 正常返回后、flush 之前调 → 卸载后 Windows
     * 看到 clean 卷免 chkdsk。block 抛异常则不调，卷停在 dirty=1，Windows 照常 chkdsk 补一致性。
     */
    override fun clearDirtyFlag() { mftMgr.clearVolumeDirty() }

    // ---- 目录操作（W12 · 可选能力）----

    override fun rename(dirFirstCluster: Long, oldName: String, newName: String): Boolean {
        mftMgr.markVolumeDirty()
        return dataOps.ntfsRename(dataOps.normDir(dirFirstCluster), oldName, newName)
    }

    override fun mkdir(dirFirstCluster: Long, name: String): Long {
        mftMgr.markVolumeDirty()
        return dataOps.ntfsMkDir(dataOps.normDir(dirFirstCluster), name)
    }

    override fun rmdir(dirFirstCluster: Long, name: String, recursive: Boolean): Boolean {
        mftMgr.markVolumeDirty()
        return dataOps.ntfsRmDir(dataOps.normDir(dirFirstCluster), name, recursive)
    }

    override fun move(srcDirFirstCluster: Long, name: String, dstDirFirstCluster: Long): Boolean {
        mftMgr.markVolumeDirty()
        return dataOps.ntfsMove(
            dataOps.normDir(srcDirFirstCluster), name, dataOps.normDir(dstDirFirstCluster)
        )
    }

    // ================= 内部访问器（供只读复用 / 自测）=================

    /** 读 MFT 第 [no] 条记录（已 USA 修复）。越界返回 null。 */
    internal fun mftRecord(no: Long) = mftMgr.readMftRecord(no)

    /** 引导扇区引用（供外部读 BPB 字段）。 */
    internal fun bootRef() = boot

    /** 索引 B+树内存自测：合成 N 项跑重建各布局，读侧回解，断言集合+顺序+签名+尺寸。 */
    internal fun ntfsIndexSelfTest(): String = index.ntfsIndexSelfTest()

    // ================= 公开 getter =================

    val readerRef: VolumeReader get() = reader
    val recordSize: Int get() = mftRecordSize
    val clusterSize: Int get() = bytesPerCluster
}
