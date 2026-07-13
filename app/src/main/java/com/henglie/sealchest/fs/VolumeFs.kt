package com.henglie.sealchest.fs

/**
 * 容器空间不足（W18）。alloc 路径（FAT/exFAT/NTFS）空闲簇不够时抛出，
 * 实现已回滚已分配簇（不留孤儿簇）。UI 捕获后提示「容器空间不足」而非通用「写入失败」。
 */
class VolumeFullException(message: String = "容器空间不足") : Exception(message)

/**
 * 卷内文件系统抽象。FAT（[FatFileSystem]）与 exFAT（[ExFatFileSystem]）都实现它，
 * 让 [MountManager] / SAF Provider / 浏览器 UI 只依赖本接口，不认具体格式。
 *
 * 全部操作经 [VolumeReader]（解密 + 逻辑寻址），实现层只见「卷内逻辑偏移」、不碰加密。
 * 线程不安全：与 [VolumeReader] 同一串行化域，所有调用都由 [MountManager] 的锁串行化。
 *
 * 句柄语义：目录 / 文件都以 [FsEntry.firstCluster]（簇号，Long）为句柄。FAT 与 exFAT
 * 都是簇号寻址，故句柄类型统一为 Long；根目录传 0（各实现自行解释为其根）。
 *
 * 目录操作（rename/mkdir/rmdir/move）为 W12 引入的可选能力：默认实现抛
 * [UnsupportedOperationException]，实现层按各自文件系统能力覆盖（纯增量，不覆盖即不支持，
 * 上层捕获异常降级提示）。这样新增操作不强制所有实现同步跟进，保证低耦合、增量安全。
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

    /**
     * 写事务**整体成功落盘后**调：清「卷脏」标记，使卸载后 Windows 挂载看到 clean 卷、
     * 免触发 chkdsk。仅 NTFS 覆盖（清 $Volume dirty 位）；FAT/exFAT 无此概念，默认空实现。
     * 崩溃安全：写事务开头 [invalidateFsInfo] 前已置脏并随数据一起 flush，任何中途崩溃
     * 卷都停在脏态 → Windows 仍 chkdsk。只有完整落盘后才清位（本方法须再 flush 持久化）。
     */
    fun clearDirtyFlag() { /* 默认空：仅 NTFS 有卷脏位 */ }

    // ---- 目录操作（W12 · 可选能力，默认不支持）----

    /**
     * 重命名目录 [dirFirstCluster] 下的条目 [oldName] 为 [newName]（文件或子目录均可）。
     * 只改目录项名字，不搬数据簇。成功返回 true。
     * 默认抛 [UnsupportedOperationException]，由具体实现按能力覆盖。
     */
    fun rename(dirFirstCluster: Long, oldName: String, newName: String): Boolean =
        throw UnsupportedOperationException("$fsType 暂不支持重命名")

    /**
     * 在目录 [dirFirstCluster] 下新建子目录 [name]。
     * 成功返回新目录首簇（> 0）；失败返回 0（或抛异常）。
     * 默认抛 [UnsupportedOperationException]。
     */
    fun mkdir(dirFirstCluster: Long, name: String): Long =
        throw UnsupportedOperationException("$fsType 暂不支持新建目录")

    /**
     * 删除目录 [dirFirstCluster] 下的子目录 [name]。
     * [recursive]=false（默认）只删空目录，非空拒绝；true 递归删除内容后删目录。
     * 成功返回 true。默认抛 [UnsupportedOperationException]。
     */
    fun rmdir(dirFirstCluster: Long, name: String, recursive: Boolean = false): Boolean =
        throw UnsupportedOperationException("$fsType 暂不支持删除目录")

    /**
     * 同卷内把 [srcDirFirstCluster] 下的条目 [name] 移动到目录 [dstDirFirstCluster]。
     * 纯目录项操作（目标 addEntry 复用首簇/size + 源 removeEntry），不搬数据簇。
     * 成功返回 true。默认抛 [UnsupportedOperationException]。
     */
    fun move(srcDirFirstCluster: Long, name: String, dstDirFirstCluster: Long): Boolean =
        throw UnsupportedOperationException("$fsType 暂不支持移动")
    /**
     * X17 卷扩展：让 FS 认领扩大的数据区（[newDataAreaSize] = 新数据区字节数，不含头组）。
     * 更新 FS 元数据（如 FAT BPB_TotSec32 / exFAT 簇堆大小 / NTFS $Volume）。
     * 成功返回 true。默认抛 [UnsupportedOperationException]（待各 FS 实现）。
     * **仅增大不缩小**，调用方保证 newDataAreaSize > 当前。
     */
    fun grow(newDataAreaSize: Long): Boolean =
        throw UnsupportedOperationException("$fsType 暂不支持卷扩展")

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
