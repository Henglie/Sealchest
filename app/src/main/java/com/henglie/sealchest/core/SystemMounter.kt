package com.henglie.sealchest.core

import com.henglie.sealchest.fs.FsEntry
import com.henglie.sealchest.fs.MountManager
import com.henglie.sealchest.fs.VolumeFs
import java.io.File
import java.io.IOException

/**
 * 系统级容器暴露（路线图 F3，root-gated）。
 *
 * ## 为什么存在
 * 主线（SAF/DocumentsProvider + 内置浏览器）只能让本 app 自己的组件、或主动走 SAF 的
 * 文件管理器访问解密卷。路线图 F3 要求：**有真 root 时**，把已解锁卷的明文文件树暴露
 * 到本机一个目录，让**任意** app（不论是否实现 SAF）都能直接 open/read。
 *
 * ## 诚实声明（重要）
 * VeraCrypt 容器是用户态加密的文件容器，**不是**标准内核可挂载格式（不是 ext4/NTFS
 * 块设备、不走 dm-crypt）。系统 `mount -o loop,encryption=...` 没有对应 VC 加密类型，
 * 纯 app 层也装不了 dm-crypt/FUSE 内核模块。因此 F3 **不是真正的内核挂载**，而是
 * 「同步暴露」：把 [com.henglie.sealchest.fs.VolumeReader] 解密出的明文文件树，遍历
 * [VolumeFs] 逐个写到目标目录。结果对其它 app 而言「能直接 open 路径读明文」，达到
 * 暴露效果；代价是明文落盘（见安全红线）。真内核挂载（loop + dm-crypt 或 FUSE 守护）
 * 需独立内核模块工程，不在此卡。
 *
 * ## 设计红线（路线图「能力分层」定，与 RootManager / BlockDeviceEnumerator 一致）
 *  - **纯增量**：无 root 或用户拒绝时，[isAvailable] 返 false，调用方隐藏入口即可，
 *    第一层（SAF / 内置浏览器）零影响。本类绝不主动请求 root（请求归
 *    [RootManager.requestRoot]）。
 *  - **默认关、知情同意才开**：明文落盘是显著增大的安全风险，调用方**必须**在用户
 *    明确同意「允许容器内容暴露于系统」后才能调 [syncExpose]。本类不替调用方做这道
 *    同意门 —— 它只提供能力、不替 UI 担责。
 *  - **绝不让主线依赖 root**：本类任何失败 / 不可用都不影响解锁 / 读写 / 创建等主线能力。
 *
 * ## 安全风险与责任
 * [syncExpose] 会把**解密后的明文**写到目标目录（如 /data/local/tmp/sealchest_exposed/）。
 * 一旦落盘，这些文件脱离了 VeraCrypt 的加密保护，任何能访问该路径的 app 都可读。因此：
 *  - 用完**必须**调 [cleanupExpose] 清掉明文；
 *  - 卷**上锁**（[MountManager.lock]）时，调用方**必须**先 [cleanupExpose] 再上锁，
 *    避免明文残留于加密保护之外；
 *  - 目标目录尽量选不可被其它用户写的位置（降低被篡改风险）；777 是为让本 app 能写、
 *    其它 app 能读，是「暴露」语义的必然代价。
 *  - 注意：现代 Android 的 SELinux 可能仍限制 app 进程写 /data/local/tmp 等 path，
 *    即便权限是 777。若 [syncExpose] 抛 IOException，调用方应换 app 可写目录重试
 *    （如 app 私有目录下再放开权限）。
 *
 * 线程：[syncExpose] 起多个 `su -c` 子进程 + 串行读 [VolumeFs]，阻塞且耗时，**必须**
 * 放后台线程。[isAvailable] / [cleanupExpose] 轻量可任意线程。
 */
object SystemMounter {

    /** 单次读盘块大小（64KB，与解密 reader 的簇 / 扇区访问粒度匹配，平衡 IO 与内存）。 */
    private const val SYNC_CHUNK = 64 * 1024

    /**
     * 是否具备系统挂载（暴露）能力。当前唯一前提是 root 已授权。
     * 不触发探测、不弹框 —— 仅返回 [RootManager.isGranted] 的快照。
     * 调用方据此决定是否显示「系统暴露」入口。
     */
    fun isAvailable(): Boolean = RootManager.isGranted()

    /**
     * 把当前已挂载卷的明文文件树同步到 [targetDir]（「同步暴露」，非内核挂载）。
     *
     * 步骤：
     *  1. root 建目录并 chmod 777（让本 app 进程能写、其它 app 能读）；
     *  2. 经 [MountManager.withFs] 在挂载锁内递归遍历 [VolumeFs]：目录 mkdir，文件用
     *     [VolumeFs.readFile] 读明文流式写到对应路径；
     *  3. 收尾 chmod -R 777，让其它 app 可读新写入的文件。
     *
     * @param targetDir 目标目录（如 /data/local/tmp/sealchest_exposed/）。会被建出。
     * @param onProgress 每处理一个条目回调一次其相对路径，供 UI 报进度。回调在调用线程同步执行。
     * @return 成功同步的**文件**数（目录不计）。
     * @throws IllegalStateException 未授权 root / 当前未挂载卷。
     * @throws IOException root 建目录失败 / 写盘失败。
     *
     * 安全：见类注释。明文落盘后必须 [cleanupExpose]；上锁前必须先清。
     */
    fun syncExpose(targetDir: File, onProgress: (String) -> Unit): Int {
        check(isAvailable()) { "未授予 root，无法做系统暴露" }
        val absPath = targetDir.absolutePath
        // 建目录 + 放开权限。777 是为了让本 app（非 root UID）能往里写文件、其它 app 能读。
        if (!execRoot("mkdir -p \"$absPath\" && chmod 777 \"$absPath\""))
            throw IOException("无法创建目标目录：$absPath")

        // 在挂载锁内串行遍历 VolumeFs。withFs 返 null = 未挂载（或刚被上锁）。
        val count = MountManager.withFs { fs ->
            val n = intArrayOf(0)
            recursiveSync(fs, fs.listRoot(), targetDir, "", onProgress, n)
            n[0]
        } ?: throw IllegalStateException("当前未挂载任何卷")

        // 收尾：把新写入的文件也放开读权限，让其它 app 可访问。
        execRoot("chmod -R 777 \"$absPath\"")
        return count
    }

    /**
     * 清理 [syncExpose] 暴露的目录：删目录下**所有内容**，但保留目录本身（便于下次复用）。
     * 需 root（明文文件可能属本 app UID，但稳妥起见用 root 删，避开权限/SELinux 坑）。
     * 未授权 root 或目录不存在时静默返回（清理操作不应抛，便于在 finally / 上锁路径无条件调）。
     *
     * 安全：这是明文落盘后的「收尾」，**必须**在用完暴露内容后调用；卷上锁前也必须调。
     */
    fun cleanupExpose(targetDir: File) {
        if (!isAvailable()) return
        val absPath = targetDir.absolutePath
        // find -mindepth 1 -delete：删目录内一切（含隐藏文件），不动目录本身，
        // 且避开 `.*` 通配会误匹配 `.`/`..` 的坑。
        execRoot("find \"$absPath\" -mindepth 1 -delete")
    }

    /**
     * 递归同步 [entries] 到 [targetDir]。
     *
     * @param prefix 当前相对 [targetDir] 的路径前缀，仅用于 [onProgress] 回调展示。
     * @param countRef 累计文件数（用 IntArray 持引用，便于在递归中累加、在外层取值）。
     */
    private fun recursiveSync(
        fs: VolumeFs,
        entries: List<FsEntry>,
        targetDir: File,
        prefix: String,
        onProgress: (String) -> Unit,
        countRef: IntArray,
    ) {
        for (entry in entries) {
            val rel = if (prefix.isEmpty()) entry.name else "$prefix/${entry.name}"
            onProgress(rel)
            val target = File(targetDir, entry.name)
            if (entry.isDirectory) {
                // 目录：直接 mkdirs（目录由 app 创建、属 app UID；收尾 chmod -R 再放开读权限）。
                if (!target.exists() && !target.mkdirs())
                    throw IOException("无法创建目录：${target.absolutePath}")
                recursiveSync(fs, fs.listDir(entry.firstCluster), target, rel, onProgress, countRef)
            } else {
                // 文件：从 VolumeFs 流式读明文写到磁盘。readFile 可能短读，循环补齐到 size。
                target.outputStream().use { out ->
                    var pos = 0L
                    while (pos < entry.size) {
                        // 先按 Long 算再 toInt，避免 > 2GB 文件在 pos 接近上界时 toInt 溢出。
                        val want = minOf(SYNC_CHUNK.toLong(), entry.size - pos).toInt()
                        if (want <= 0) break
                        val chunk = fs.readFile(entry.firstCluster, entry.size, pos, want)
                        if (chunk.isEmpty()) break // EOF 或读不出，止损，避免死循环
                        out.write(chunk)
                        pos += chunk.size
                    }
                }
                countRef[0]++
            }
        }
    }

    /**
     * 用 root 执行 [cmd]（`su -c`）。成功（exit 0）返 true，否则 false。
     * 排空 stdout 避免子进程因管道满而阻塞。失败（无 su / 异常）返 false，不抛。
     */
    private fun execRoot(cmd: String): Boolean = runCatching {
        val process = ProcessBuilder("su", "-c", cmd)
            .redirectErrorStream(true)
            .start()
        process.inputStream.bufferedReader().use { it.readText() }
        process.waitFor() == 0
    }.getOrDefault(false)
}
