package com.henglie.sealchest.fs

import android.content.ContentResolver
import android.net.Uri
import com.henglie.sealchest.crypto.KeyfileMixer
import com.henglie.sealchest.crypto.NativeBridge
import java.io.FileNotFoundException
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer

/**
 * VeraCrypt 卷头备份 / 恢复（救砖）。
 *
 * 全程对容器文件做**原始字节 I/O，不经加解密**——卷头本身是自包含的加密块
 * （前 64 字节 salt 明文 + 用 header key 加密的主密钥区），原样拷贝即可、也只能原样拷贝，
 * 解密它没有意义。正因如此，即使「主头损坏、密码对也开不了卷」，只要卷尾备份头还在，
 * 就能靠本工具救回来——这是 A2 存在的全部理由。
 *
 * VeraCrypt 卷布局（标准非 legacy，与本项目 encStart=131072 实测一致，见 PROGRESS 踩坑）：
 * ```
 *   [0,       64KB)   主卷头        （64KB 区，有效 512B，salt 在前 64B）
 *   [64KB,   128KB)   主隐藏卷头     （64KB 区）
 *   [128KB,  size-128KB)  数据区（encStart = 128KB = TC_VOLUME_HEADER_GROUP_SIZE）
 *   [size-128KB, size-64KB)  备份卷头      （64KB 区）   ← 救砖来源
 *   [size-64KB,  size)       备份隐藏卷头   （64KB 区）
 * ```
 * 前 128KB = 主头组，后 128KB = 备份头组。恢复 = 把备份头组整体覆盖到主头组。
 *
 * **不需挂载**：所有操作在解锁前对选中的容器 URI 直接做，正是为「打不开时救砖」设计。
 * 调用方须保证此时容器未被 [MountManager] 挂载（同一文件双写会互相踩）。
 *
 * 安全前置（写头区 = 可砖，不可逆）：任何恢复（写）操作在覆盖前必须
 *   ① 用用户密码 + keyfile 验证「源头能开卷」——源头也坏 / 密码错则拒绝写，绝不用垃圾覆盖；
 *   ② 先把当前主头组导出到一个救援文件（万一恢复后更糟，还能退回原样）。
 */
object VolumeHeaderTool {

    /** 卷头有效字节数（TC_VOLUME_HEADER_EFFECTIVE_SIZE）。openVolume 只看前 512B。 */
    const val HEADER_EFFECTIVE = 512

    /** 主头组 / 备份头组各自大小（TC_VOLUME_HEADER_GROUP_SIZE = 主头 64KB + 隐藏头 64KB）。 */
    const val HEADER_GROUP = 128 * 1024

    /** 主头组 + 备份头组不重叠的容器下限。小于此无独立备份头，救砖不适用。 */
    const val MIN_VOLUME_SIZE = 2L * HEADER_GROUP

    /**
     * 备份主头组到外部文件 [destUri]（原始 128KB 转储）。只读容器，最安全。
     *
     * 注意：这是 **Sealchest 自己的卷头备份**，可用本工具的 [restoreFromFile] 恢复。
     * 与桌面 VeraCrypt「外部备份文件」格式是否互通**未经验证**，勿依赖用它去喂桌面 VC。
     * 真正与 VC 互通的是 [restoreFromEmbedded]（全程在容器内，格式天然一致）。
     */
    fun export(resolver: ContentResolver, containerUri: Uri, destUri: Uri): Result<Unit> = runCatching {
        val group = readRaw(resolver, containerUri, 0L, HEADER_GROUP)
        resolver.openOutputStream(destUri)?.use { it.write(group) }
            ?: throw FileNotFoundException("无法写备份文件")
    }

    /**
     * 救砖核心：把卷尾备份头组整体覆盖到卷首主头组。
     *
     * @param rescueDestUri 覆盖前把**当前主头组**导出到此文件（可逆兜底），必须可写。
     * @throws SecurityException 备份头无法用此密码/keyfile 打开（备份也坏或密码错）→ 不写。
     * @throws IllegalArgumentException 容器过小、无独立备份头。
     */
    fun restoreFromEmbedded(
        resolver: ContentResolver,
        containerUri: Uri,
        password: ByteArray,
        pim: Int,
        prf: Int,
        keyfiles: List<ByteArray>,
        rescueDestUri: Uri,
        autoRescueFile: File? = null,
    ): Result<Unit> = runCatching {
        val size = fileSize(resolver, containerUri)
        require(size >= MIN_VOLUME_SIZE) { "容器过小（<256KB），无独立备份头，无法救砖" }

        val backupGroupOffset = size - HEADER_GROUP
        val backupGroup = readRaw(resolver, containerUri, backupGroupOffset, HEADER_GROUP)

        // ① 验证备份头能开卷（否则备份也坏 / 密码错，拒绝写）。
        verifyOpens(backupGroup.copyOf(HEADER_EFFECTIVE), password, pim, prf, keyfiles)

        // ② 兜底：先把当前主头组存出去。
        rescueCurrentPrimary(resolver, containerUri, rescueDestUri, autoRescueFile)

        // ③ 覆盖：备份头组 → 主头组。
        writeRaw(resolver, containerUri, 0L, backupGroup)
    }

    /**
     * 从 Sealchest 备份文件 [backupUri]（[export] 产物，128KB）恢复主头组。
     *
     * @throws SecurityException 备份文件里的头无法用此密码/keyfile 打开 → 不写。
     * @throws IllegalArgumentException 备份文件大小不符（应 ≥128KB）。
     */
    fun restoreFromFile(
        resolver: ContentResolver,
        containerUri: Uri,
        backupUri: Uri,
        password: ByteArray,
        pim: Int,
        prf: Int,
        keyfiles: List<ByteArray>,
        rescueDestUri: Uri,
        autoRescueFile: File? = null,
    ): Result<Unit> = runCatching {
        val group = resolver.openInputStream(backupUri)?.use { it.readBytes() }
            ?: throw FileNotFoundException("无法读备份文件")
        require(group.size >= HEADER_GROUP) { "备份文件不是有效卷头备份（应为 128KB）" }

        // ① 验证备份文件里的头能开卷。
        verifyOpens(group.copyOf(HEADER_EFFECTIVE), password, pim, prf, keyfiles)

        // ② 兜底 + ③ 覆盖。
        rescueCurrentPrimary(resolver, containerUri, rescueDestUri, autoRescueFile)
        writeRaw(resolver, containerUri, 0L, group.copyOf(HEADER_GROUP))
    }

    // ---------------- 内部 ----------------

    /** 用密码+keyfile 派生并试开 [header512]；开不开就抛，绝不返回让调用方误写。 */
    private fun verifyOpens(
        header512: ByteArray, password: ByteArray, pim: Int, prf: Int, keyfiles: List<ByteArray>,
    ) {
        check(NativeBridge.isAvailable) { "加密核心库未加载" }
        val eff = KeyfileMixer.apply(password, keyfiles)
        try {
            val v = NativeBridge.openVolume(header512, eff, pim, prf)
                ?: throw SecurityException("源卷头无法用此密码 / keyfile 打开（备份头也已损坏，或密码 / PIM / PRF 错）")
            v.close()
        } finally {
            eff.fill(0)
        }
    }

    /** 把当前主头组（128KB）导出到 [rescueDestUri]，作为恢复前的可逆兜底。 */
    private fun rescueCurrentPrimary(
        resolver: ContentResolver, containerUri: Uri, rescueDestUri: Uri, autoRescueFile: File?,
    ) {
        val current = readRaw(resolver, containerUri, 0L, HEADER_GROUP)
        resolver.openOutputStream(rescueDestUri)?.use { it.write(current) }
            ?: throw FileNotFoundException("无法写救援备份文件——恢复已中止，未改动容器")
        autoRescueFile?.let { f -> runCatching { f.writeBytes(current) } }
    }

    /** 原始读：容器 [offset] 起 [len] 字节。只读打开，位置寻址，不动加解密。 */
    private fun readRaw(resolver: ContentResolver, uri: Uri, offset: Long, len: Int): ByteArray {
        val pfd = resolver.openFileDescriptor(uri, "r")
            ?: throw FileNotFoundException("无法打开容器：$uri")
        pfd.use {
            java.io.FileInputStream(it.fileDescriptor).channel.use { ch ->
                val buf = ByteArray(len)
                val bb = ByteBuffer.wrap(buf)
                var pos = offset
                while (bb.hasRemaining()) {
                    val n = ch.read(bb, pos)
                    if (n < 0) break
                    pos += n
                }
                return buf
            }
        }
    }

    /**
     * 原始写：把 [data] 写到容器 [offset] 处。经 /proc/self/fd 拿双向 channel
     * （与 MountManager 同一手法，SAF PFD + FileChannel 写只能这样）。写后 force 落盘。
     * 只覆盖 [data] 长度的字节，不改文件大小、不截断。
     */
    private fun writeRaw(resolver: ContentResolver, uri: Uri, offset: Long, data: ByteArray) {
        val pfd = resolver.openFileDescriptor(uri, "rw")
            ?: throw FileNotFoundException("无法以可写方式打开容器：$uri（需已授予写权限）")
        pfd.use {
            RandomAccessFile("/proc/self/fd/${it.fd}", "rw").use { raf ->
                val ch = raf.channel
                val bb = ByteBuffer.wrap(data)
                var pos = offset
                while (bb.hasRemaining()) {
                    val n = ch.write(bb, pos)
                    if (n < 0) break
                    pos += n
                }
                ch.force(false)
            }
        }
    }

    /** 容器文件字节数。statSize 不可靠时回落 channel.size()。 */
    private fun fileSize(resolver: ContentResolver, uri: Uri): Long {
        val pfd = resolver.openFileDescriptor(uri, "r")
            ?: throw FileNotFoundException("无法打开容器：$uri")
        pfd.use {
            val s = it.statSize
            if (s > 0) return s
            java.io.FileInputStream(it.fileDescriptor).channel.use { ch -> return ch.size() }
        }
    }
}
