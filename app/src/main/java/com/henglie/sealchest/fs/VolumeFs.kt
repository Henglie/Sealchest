package com.henglie.sealchest.fs

/**
 * 卷内文件系统抽象。FAT（[FatFileSystem]）与 exFAT（[ExFatFileSystem]）都实现它，
 * 让 [MountManager] / SAF Provider / 浏览器 UI 只依赖本接口，不认具体格式。
 *
 * 全部操作经 [VolumeReader]（解密 + 逻辑寻址），实现层只见「卷内逻辑偏移」、不碰加密。
 * 线程不安全：与 [VolumeReader] 同一串行化域，所有调用都由 [MountManager] 的锁串行化。
 *
 * 句柄语义：目录 / 文件都以 [FsEntry.firstCluster]（簇号，Long）为句柄。FAT 与 exFAT
 * 都是簇号寻址，故句柄类型统一为 Long；根目录传 0（各实现自行解释为其根）。
 */
interface VolumeFs {

    /** 文件系统类型串，仅供展示（"FAT12" / "FAT16" / "FAT32" / "exFAT"）。 */
    val fsType: String

    /** 卷标；无卷标为空串。 */
    val volumeLabel: String

    // ---- 只读 ----

    /** 列根目录。 */
    fun listRoot(): List<FsEntry>

    /** 列 [firstCluster] 指向的子目录。 */
    fun listDir(firstCluster: Long): List<FsEntry>

    /**
     * 读文件 [firstCluster] 的 [start] 起 [length] 字节（受 [fileSize] 截断）。
     * 返回实际读到的字节（可能短于 length）。
     */
    fun readFile(firstCluster: Long, fileSize: Long, start: Long, length: Int): ByteArray

    /**
     * 已用数据区上界（卷内逻辑偏移）：扫分配表找最高已用簇，返回其后一字节偏移。
     * 隐藏卷创建据此算安全区，避免踩踏外层已有文件。空卷返回数据区起点。
     */
    fun usedDataAreaUpperBound(): Long

    // ---- 写 ----

    /** 在目录 [dirFirstCluster] 下新建文件 [name] 写入 [bytes]。成功返回 true。 */
    fun writeFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean

    /** 覆写目录 [dirFirstCluster] 下已有文件 [name] 为 [bytes]。成功返回 true。 */
    fun overwriteFile(dirFirstCluster: Long, name: String, bytes: ByteArray): Boolean

    /** 删除目录 [dirFirstCluster] 下的文件 [name]。成功返回 true。 */
    fun deleteFile(dirFirstCluster: Long, name: String): Boolean

    /**
     * 写操作收尾：让空闲计数元数据失效（FAT32 FSInfo 置 unknown 让 OS 重算）。
     * 无此类元数据的格式（FAT12/16 / exFAT 简版）为空实现。
     */
    fun invalidateFsInfo()
}

/**
 * 一个目录条目：文件或子目录。FAT 与 exFAT 共用。
 */
data class FsEntry(
    val name: String,
    val isDirectory: Boolean,
    val size: Long,
    /** 起始簇号；0 表示空文件 / 空目录。 */
    val firstCluster: Long,
    /** 时间戳合成的毫秒（本地时区语义，仅供展示）。 */
    val lastModified: Long,
)

/** FAT 类型。顶层定义，供 [Bpb] 与 [FatFileSystem] 共用（避免循环依赖）。 */
enum class FatType { FAT12, FAT16, FAT32 }
