package com.henglie.sealchest.fs

import android.content.ContentResolver
import android.net.Uri
import com.henglie.sealchest.crypto.KeyfileMixer
import com.henglie.sealchest.crypto.NativeBridge
import java.io.File
import java.io.FileNotFoundException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.security.SecureRandom

/**
 * X17 卷扩展（仅增大不缩小）—— 字节级对齐 VeraCrypt `ExpandVolume` 思路。
 *
 * 核心不变式：**主密钥不动，只换头 + 扩文件**。扩展不重加密旧数据区，只是：
 *   ① 用原口令开卷（验证 + 拿主密钥句柄）。
 *   ② [NativeBridge.Volume.expandHeaders]：复用主密钥，用原口令 + 原 PRF/PIM 重加密头，
 *      只把 VolumeSize/EncryptedAreaLength 改为新大小。
 *   ③ 扩文件到新总大小（追加零字节到文件尾）。
 *   ④ 写新备份头到新偏移（HEADER_GROUP + newVolumeSize）。
 *   ⑤ 写新主头到偏移 0（= 提交点：主头一更新，扩展即生效）。
 *   ⑥ 校验：用原口令重新开主头，确认新 volumeSize 正确。
 *
 * 崩溃安全：
 *   - ③④ 之后、⑤ 之前崩溃 → 主头仍为旧大小，卷按旧大小可用，扩展区是多余零字节。
 *   - ⑤ 之后崩溃 → 两头均为新大小，卷按新大小可用。FS 元数据尚未更新则 FS 看不到
 *     新增空间（安全，无损坏），需重新挂载后调 [VolumeFs.grow] 让 FS 认领新空间。
 *
 * 与 [PasswordChanger] 同层、同手法（绝对偏移原始 I/O + /proc/self/fd 写 +
 * 写前 rescue 兜底）。调用方须保证容器**未被 [MountManager] 挂载**。
 *
 * **FS 元数据更新不在本类职责内**（低耦合）：本类只做容器级扩展（头 + 文件）。
 * 扩展后调用方应重新挂载，再调 [VolumeFs.grow] 让 FS 认领新增空间。
 * 当前各 FS 的 grow 默认抛 UnsupportedOperationException（待各 FS 实现）。
 */
object VolumeExpander {

    /** 卷头有效字节数（TC_VOLUME_HEADER_EFFECTIVE_SIZE）。 */
    private const val HEADER_EFFECTIVE = 512

    /** 主头组 / 备份头组各自大小（TC_VOLUME_HEADER_GROUP_SIZE = 128KB）。 */
    private const val HEADER_GROUP = 128 * 1024L

    /**
     * 扩展卷。成功返回新旧数据区大小，失败抛异常。
     *
     * @param containerUri 容器文件 URI（须已授予写权限）。
     * @param password 当前口令 UTF-8 字节（可空长度 0，配合 keyfile）。
     * @param pim 当前 PIM（0 = 默认）。
     * @param prf 当前 PRF（传 [NativeBridge.PRF_AUTO] 让核心自探）。
     * @param keyfiles 当前 keyfile 内容列表（空 = 无）。
     * @param newDataAreaSize 新数据区字节数（不含头组），须 > 当前且 512 对齐。
     * @param rescueDestUri 写头前把当前主头组导出到此（可逆兜底），必须可写。
     * @return Pair(旧数据区大小, 新数据区大小)。
     */
    fun expand(
        resolver: ContentResolver,
        containerUri: Uri,
        password: ByteArray,
        pim: Int,
        prf: Int,
        keyfiles: List<ByteArray>,
        newDataAreaSize: Long,
        rescueDestUri: Uri,
        autoRescueFile: File? = null,
    ): Result<Pair<Long, Long>> = runCatching {
        check(NativeBridge.isAvailable) { "加密核心库未加载" }
        require(newDataAreaSize % 512L == 0L) { "新大小须 512 对齐：$newDataAreaSize" }

        val oldFileSize = fileSize(resolver, containerUri)
        require(oldFileSize >= 2L * HEADER_GROUP) { "容器过小（<256KB），无独立备份头" }

        // ① 读主头 512B，用原口令开卷（验证 + 拿主密钥句柄）。
        val primaryHeader = readRaw(resolver, containerUri, 0L, HEADER_EFFECTIVE)
        val eff = KeyfileMixer.apply(password, keyfiles)
        val volume = try {
            NativeBridge.openVolume(primaryHeader, eff, pim, prf)
        } finally {
            eff.fill(0)
        } ?: throw SecurityException("口令、PIM、PRF 或 keyfile 不正确")

        val oldDataSize = volume.volumeSize
        require(newDataAreaSize > oldDataSize) {
            "新大小须大于当前：$newDataAreaSize <= $oldDataSize（仅增大不缩小）"
        }

        // 校验新总大小不超过合理上限（防溢出 / 超大值打满磁盘）。
        val newTotalSize = HEADER_GROUP + newDataAreaSize + HEADER_GROUP
        require(newTotalSize > oldFileSize) { "新总大小须大于旧总大小" }

        val newHeaders: Pair<ByteArray, ByteArray>
        try {
            // ② 灌熵：expand 内部各取新随机盐。
            val entropy = ByteArray(4096)
            try {
                SecureRandom().nextBytes(entropy)
                NativeBridge.seedRandom(entropy)
            } finally {
                entropy.fill(0)
            }

            // ③ 重加密头（复用主密钥 + 原口令 + 原 PRF/PIM，只改 VolumeSize）。
            val expandEff = KeyfileMixer.apply(password, keyfiles)
            try {
                newHeaders = volume.expandHeaders(newDataAreaSize, expandEff)
                    ?: throw IllegalStateException("卷头重加密失败（熵不足或参数错）")
            } finally {
                expandEff.fill(0)
            }
        } finally {
            volume.close()
        }

        val (newPrimary, newBackup) = newHeaders
        try {
            // ④ 兜底：先导出当前主头组（可逆）。
            rescueCurrentPrimary(resolver, containerUri, rescueDestUri, autoRescueFile)

            val newBackupOffset = HEADER_GROUP + newDataAreaSize

            // ⑤ 扩文件 + 写新备份头 + 写新主头（提交）。
            val pfd = resolver.openFileDescriptor(containerUri, "rw")
                ?: throw FileNotFoundException("无法以可写方式打开容器（需已授予写权限）")
            pfd.use {
                RandomAccessFile("/proc/self/fd/${it.fd}", "rw").use { raf ->
                    val ch = raf.channel
                    // 扩文件到新总大小（追加零字节）。
                    if (ch.size() < newTotalSize) {
                        raf.setLength(newTotalSize)
                    }
                    // 写新备份头到新偏移。
                    writeAbsolute(ch, newBackupOffset, newBackup, HEADER_EFFECTIVE)
                    // 写新主头到偏移 0（= 提交点）。
                    writeAbsolute(ch, 0L, newPrimary, HEADER_EFFECTIVE)
                    ch.force(false)
                }
            }

            // ⑥ 校验：用原口令重新开主头，确认新 volumeSize 正确。
            val verifyHeader = readRaw(resolver, containerUri, 0L, HEADER_EFFECTIVE)
            val verifyEff = KeyfileMixer.apply(password, keyfiles)
            try {
                val v = NativeBridge.openVolume(verifyHeader, verifyEff, pim, prf)
                    ?: throw IllegalStateException(
                        "扩展后校验失败——卷头可能写坏。请用「卷头工具」从救援文件恢复。"
                    )
                try {
                    check(v.volumeSize == newDataAreaSize) {
                        "扩展后卷头 volumeSize 不匹配：期望 $newDataAreaSize，实际 ${v.volumeSize}"
                    }
                } finally {
                    v.close()
                }
            } finally {
                verifyEff.fill(0)
            }
        } finally {
            newPrimary.fill(0)
            newBackup.fill(0)
        }

        Pair(oldDataSize, newDataAreaSize)
    }

    // ---------------- 内部（复刻 PasswordChanger 的原始 I/O 手法）----------------

    private fun rescueCurrentPrimary(
        resolver: ContentResolver, containerUri: Uri, rescueDestUri: Uri, autoRescueFile: File?,
    ) {
        val current = readRaw(resolver, containerUri, 0L, HEADER_GROUP.toInt())
        autoRescueFile?.let { f -> runCatching { f.writeBytes(current) } }
        resolver.openOutputStream(rescueDestUri)?.use { it.write(current) }
            ?: throw FileNotFoundException("无法写救援备份文件——扩展已中止，未改动容器")
    }

    private fun writeAbsolute(
        ch: FileChannel, offset: Long, src: ByteArray, length: Int,
    ) {
        val bb = ByteBuffer.wrap(src, 0, length)
        var pos = offset
        while (bb.hasRemaining()) {
            val n = ch.write(bb, pos)
            if (n < 0) break
            pos += n
        }
    }

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
