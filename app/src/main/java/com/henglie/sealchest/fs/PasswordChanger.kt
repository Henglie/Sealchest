package com.henglie.sealchest.fs

import android.content.ContentResolver
import android.net.Uri
import com.henglie.sealchest.crypto.KeyfileMixer
import com.henglie.sealchest.crypto.NativeBridge
import java.io.FileNotFoundException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * B1 改密码 / PIM / PRF / keyfile —— 字节级复刻 VeraCrypt `ChangePwd`（Common/Password.c:190）。
 *
 * 核心不变式：**主密钥不动，只换头**。改密码不重加密数据区，只是用新口令 + 新盐
 * 重新派生 header key、把同一个主密钥重新加密进主头 + 备份头。所以「改密码」在 VC 里
 * 是个极快、极安全的操作——数据一个字节都不动，旧口令派生的 header key 作废。
 *
 * 流程（对容器 URI 直接做原始字节 I/O，不经挂载）：
 *   ① 读主头组前 512B，用**旧**口令 + keyfile 开卷 —— 拿到持有旧主密钥的句柄，
 *      同时验证旧口令正确（错则直接失败，不动容器）。
 *   ② 灌熵（[NativeBridge.seedRandom]）—— rekey 内部各取新随机盐用。
 *   ③ [NativeBridge.Volume.rekeyHeaders]：复用旧主密钥，用**新**口令重加密主头 + 备份头，
 *      得到两个新的 512B 有效头（其余卷参数从旧 cryptoInfo 原样透传，字节级对齐 VC）。
 *   ④ 兜底：先把当前主头组（128KB）导出到 [rescueDestUri]（可逆，万一写坏能退回）。
 *   ⑤ 写新主头 512B → 文件偏移 0；写新备份头 512B → 卷尾备份头组起始（size-128KB）。
 *   ⑥ 校验：用**新**口令重新开主头，开得了才算成功；开不了视为写坏，抛错让用户用
 *      rescue 文件恢复。
 *
 * 与 [VolumeHeaderTool]（A2 救砖）同层、同手法（绝对偏移原始 I/O + /proc/self/fd 写 +
 * 写前 rescue 兜底），互为安全网：改密码失败可用 A2 从 rescue 文件或卷尾备份头救回。
 *
 * 调用方须保证此时容器**未被 [MountManager] 挂载**（同一文件双写互踩）。
 */
object PasswordChanger {

    /** 卷头有效字节数（TC_VOLUME_HEADER_EFFECTIVE_SIZE）。 */
    private const val HEADER_EFFECTIVE = 512

    /** 主头组 / 备份头组各自大小（TC_VOLUME_HEADER_GROUP_SIZE）。 */
    private const val HEADER_GROUP = 128 * 1024

    /** 主头组 + 备份头组不重叠的容器下限。 */
    private const val MIN_VOLUME_SIZE = 2L * HEADER_GROUP

    /**
     * 改口令。成功返回 Unit，失败抛异常（旧口令错 / 熵不足 / 写失败 / 校验失败）。
     *
     * @param oldPassword 当前口令 UTF-8 字节（可空长度 0，配合 keyfile）。
     * @param oldPim / oldPrf 当前 PIM / PRF（开旧卷用；oldPrf 传 [NativeBridge.PRF_AUTO] 让核心自探）。
     * @param oldKeyfiles 当前 keyfile 内容列表（空 = 无）。
     * @param newPassword 新口令 UTF-8 字节（可空长度 0，配合新 keyfile）。
     * @param newPim 新 PIM（0 = 默认）。
     * @param newPrf 新 PRF ID；传 0 保持原卷 PRF。
     * @param newKeyfiles 新 keyfile 内容列表（空 = 无）。
     * @param rescueDestUri 写头前把当前主头组导出到此（可逆兜底），必须可写。
     */
    fun change(
        resolver: ContentResolver,
        containerUri: Uri,
        oldPassword: ByteArray,
        oldPim: Int,
        oldPrf: Int,
        oldKeyfiles: List<ByteArray>,
        newPassword: ByteArray,
        newPim: Int,
        newPrf: Int,
        newKeyfiles: List<ByteArray>,
        rescueDestUri: Uri,
    ): Result<Unit> = runCatching {
        check(NativeBridge.isAvailable) { "加密核心库未加载" }

        val size = fileSize(resolver, containerUri)
        require(size >= MIN_VOLUME_SIZE) { "容器过小（<256KB），无独立备份头，无法安全改密码" }
        val backupHeaderOffset = size - HEADER_GROUP

        // ① 读主头 512B，用旧口令 + keyfile 开卷（验证 + 拿旧主密钥句柄）。
        val primaryHeader = readRaw(resolver, containerUri, 0L, HEADER_EFFECTIVE)
        val oldEff = KeyfileMixer.apply(oldPassword, oldKeyfiles)
        val volume = try {
            NativeBridge.openVolume(primaryHeader, oldEff, oldPim, oldPrf)
        } finally {
            oldEff.fill(0)
        } ?: throw SecurityException("旧口令、PIM、PRF 或 keyfile 不正确，无法改密码")

        val newHeaders: Pair<ByteArray, ByteArray>
        val newEff = KeyfileMixer.apply(newPassword, newKeyfiles)
        try {
            // ② 灌熵：rekey 内部各取新随机盐（RandgetBytes 池空返 FALSE 即失败，绝不吐可预测盐）。
            val entropy = ByteArray(4096)
            try {
                SecureRandom().nextBytes(entropy)
                NativeBridge.seedRandom(entropy)
            } finally {
                entropy.fill(0)
            }

            // ③ 用新口令重加密主头 + 备份头（复用旧主密钥）。
            newHeaders = volume.rekeyHeaders(newPrf, newPim, newEff)
                ?: throw IllegalStateException("卷头重加密失败（熵不足或参数错）")
        } finally {
            newEff.fill(0)
            volume.close()   // 销毁旧主密钥句柄
        }

        val (newPrimary, newBackup) = newHeaders
        check(newPrimary.size >= HEADER_EFFECTIVE && newBackup.size >= HEADER_EFFECTIVE) {
            "重加密返回的卷头长度异常"
        }

        try {
            // ④ 兜底：先导出当前主头组（可逆）。
            rescueCurrentPrimary(resolver, containerUri, rescueDestUri)

            // ⑤ 写新主头 @0、新备份头 @卷尾备份头组起始。
            writeHeaders(resolver, containerUri, backupHeaderOffset, newPrimary, newBackup)

            // ⑥ 校验：新口令能重新开主头，才算真正成功。
            val verifyHeader = readRaw(resolver, containerUri, 0L, HEADER_EFFECTIVE)
            val verifyEff = KeyfileMixer.apply(newPassword, newKeyfiles)
            try {
                val v = NativeBridge.openVolume(verifyHeader, verifyEff, newPim, newPrf)
                    ?: throw IllegalStateException(
                        "改密码后新口令校验失败——卷头可能写坏。请用「卷头工具」从救援文件 " +
                            "或卷尾备份头恢复。"
                    )
                v.close()
            } finally {
                verifyEff.fill(0)
            }
        } finally {
            newPrimary.fill(0)
            newBackup.fill(0)
        }
    }

    // ---------------- 内部（复刻 VolumeHeaderTool 的原始 I/O 手法）----------------

    /** 把当前主头组（128KB）导出到 [rescueDestUri]，作为写头前的可逆兜底。 */
    private fun rescueCurrentPrimary(resolver: ContentResolver, containerUri: Uri, rescueDestUri: Uri) {
        val current = readRaw(resolver, containerUri, 0L, HEADER_GROUP)
        resolver.openOutputStream(rescueDestUri)?.use { it.write(current) }
            ?: throw FileNotFoundException("无法写救援备份文件——改密码已中止，未改动容器")
    }

    /**
     * 写新主头 [primary]（→偏移 0）与新备份头 [backup]（→[backupHeaderOffset]），各 512B。
     * 经 /proc/self/fd 拿双向 channel（SAF PFD 写只能这样），写后 force 落盘。
     * 只覆盖各 512B 有效头，不动头组内其余字节、不改文件大小。
     */
    private fun writeHeaders(
        resolver: ContentResolver,
        containerUri: Uri,
        backupHeaderOffset: Long,
        primary: ByteArray,
        backup: ByteArray,
    ) {
        val pfd = resolver.openFileDescriptor(containerUri, "rw")
            ?: throw FileNotFoundException("无法以可写方式打开容器（需已授予写权限）")
        pfd.use {
            RandomAccessFile("/proc/self/fd/${it.fd}", "rw").use { raf ->
                val ch = raf.channel
                writeAbsolute(ch, 0L, primary, HEADER_EFFECTIVE)
                writeAbsolute(ch, backupHeaderOffset, backup, HEADER_EFFECTIVE)
                ch.force(false)
            }
        }
    }

    private fun writeAbsolute(
        ch: java.nio.channels.FileChannel, offset: Long, src: ByteArray, length: Int,
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
