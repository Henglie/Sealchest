package com.henglie.sealchest.core

import android.content.Context
import com.henglie.sealchest.crypto.KeyfileMixer
import com.henglie.sealchest.crypto.NativeBridge
import com.henglie.sealchest.fs.ExFatBoot
import com.henglie.sealchest.fs.FatFileSystem
import com.henglie.sealchest.fs.NtfsBoot
import com.henglie.sealchest.fs.NtfsFileSystem
import com.henglie.sealchest.fs.ExFatFileSystem
import com.henglie.sealchest.fs.VolumeFs
import com.henglie.sealchest.fs.VolumeReader
import com.henglie.sealchest.core.Settings
import java.io.File
import java.io.RandomAccessFile

/**
 * 块设备 / 物理分区加密解锁（路线图 F2）。需 root（[RootManager.isGranted]）。
 *
 * 与 [com.henglie.sealchest.fs.MountManager.unlock] 的差异：
 *  - 文件容器经 SAF（ContentResolver + PFD）拿 FileChannel。
 *  - 块设备经 root 用 `RandomAccessFile("/dev/block/xxx", "r"/"rw")` 直接打开设备节点拿 FileChannel。
 *  - 其余（读卷头 → openVolume → VolumeReader → FS 分发）完全复用同一套逻辑。
 *
 * 支持只读与可写解锁：
 *  - 只读：`RandomAccessFile("r")`，仅读不写。
 *  - 可写：`RandomAccessFile("rw")`，VolumeReader.write/flush 可回写块设备。
 *
 * 设计红线（路线图「能力分层」定）：
 *  - **纯增量**：无 root 时本类所有方法抛异常 / 返 null，第一层（文件容器主线）零影响。
 *  - **绝不让主线依赖 root**。
 *
 * 线程：[unlock] 会起 root 子进程开设备节点，阻塞，放后台线程。
 */
object BlockDeviceUnlocker {

    /** 隐藏卷头偏移（与 MountManager 一致，TC_HIDDEN_VOLUME_HEADER_OFFSET = 64KB）。 */
    private const val HIDDEN_VOLUME_HEADER_OFFSET = 64L * 1024

    /**
     * 已解锁的块设备挂载。调用方负责 [close]（关 reader + RandomAccessFile）。
     * 与 [com.henglie.sealchest.fs.MountManager.Mount] 平行，但不进 MountManager 全局态
     * （块设备挂载是独立路径，不与文件容器混用全局单例）。
     */
    class BlockMount internal constructor(
        val devicePath: String,
        internal val reader: VolumeReader,
        val fs: VolumeFs,
        val writable: Boolean,
        private val raf: RandomAccessFile,
    ) : AutoCloseable {
        override fun close() {
            runCatching { reader.close() }
            runCatching { raf.close() }
        }
    }

    /**
     * 解锁并挂载块设备 [devicePath]（如 /dev/block/sda23）。
     *
     * @param devicePath 块设备节点路径（来自 [BlockDeviceEnumerator]）。
     * @param password 口令 UTF-8 字节。
     * @param writable 是否可写挂载（true=读写，false=只读）。可写用 "rw" 打开设备节点。
     * @param pim PIM（0=默认）。
     * @param prf PRF（[NativeBridge.PRF_AUTO] 自探）。
     * @param keyfiles keyfile 内容列表。
     * @return 解锁的 [BlockMount]，失败抛异常。
     *
     * @throws IllegalStateException root 未授权 / native 核心不可用。
     * @throws SecurityException 口令不对。
     * @throws IllegalArgumentException 卷内不是可识别的 FAT/exFAT/NTFS。
     */
    fun unlock(
        context: Context,
        devicePath: String,
        password: ByteArray,
        writable: Boolean = false,
        pim: Int = 0,
        prf: Int = NativeBridge.PRF_AUTO,
        keyfiles: List<ByteArray> = emptyList(),
    ): BlockMount {
        check(NativeBridge.isAvailable) { "加密核心库未加载" }
        check(RootManager.isGranted()) { "块设备解锁需 root 授权" }
        require(devicePath.startsWith("/dev/block/")) { "仅允许 /dev/block/ 下设备节点：$devicePath" }

        // 用 root 打开块设备节点。只读走 "r"，可写走 "rw"。
        // 非 root 进程无权 open /dev/block/*，需 root 授权后进程才具备。
        val raf = RandomAccessFile(devicePath, if (writable) "rw" else "r")
        val channel = raf.channel

        try {
            // 读卷头（512B 自包含加密块）。
            fun readHeaderAt(offset: Long): ByteArray {
                val h = ByteArray(512)
                val hb = java.nio.ByteBuffer.wrap(h)
                var pos = offset
                while (hb.hasRemaining()) {
                    val n = channel.read(hb, pos)
                    if (n < 0) break
                    pos += n
                }
                return h
            }

            val effective = KeyfileMixer.apply(password, keyfiles)
            val volume = try {
                // 先主头（偏移 0），再隐藏头（64KB），与 MountManager 一致。
                NativeBridge.openVolume(readHeaderAt(0L), effective, pim, prf)
                    ?: NativeBridge.openVolume(readHeaderAt(HIDDEN_VOLUME_HEADER_OFFSET), effective, pim, prf)
            } finally {
                effective.fill(0)
            } ?: throw SecurityException("密码、PIM、PRF 或 keyfile 不正确（块设备）")

            val reader = VolumeReader(channel, volume)

            // FS 分发（与 MountManager 一致，NTFS 同样受实验开关控制）。
            val boot0 = reader.read(0, 512)
            val fs: VolumeFs = when {
                NtfsBoot.isNtfs(boot0) -> NtfsFileSystem.mount(reader)
                ExFatBoot.isExFat(boot0) -> ExFatFileSystem.mount(reader)
                else -> FatFileSystem.mount(reader)
            }

            return BlockMount(devicePath, reader, fs, writable, raf)
        } catch (t: Throwable) {
            // 失败清理，绝不留半成品。
            runCatching { raf.close() }
            password.fill(0)
            throw t
        }
    }
}
