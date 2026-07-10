package com.henglie.sealchest.fs

import android.content.ContentResolver
import android.net.Uri
import com.henglie.sealchest.crypto.KeyfileMixer
import com.henglie.sealchest.crypto.NativeBridge
import java.io.FileNotFoundException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.security.SecureRandom

/**
 * C2 在已有外层容器内创建隐藏卷。字节级复刻 VeraCrypt Format.c 隐藏卷分支。
 *
 * 隐藏卷是**独立的新卷**（自己的随机主密钥），寄生在外层卷数据区尾部、备份头组之前：
 * ```
 *   [0,      64KB)          外层主卷头
 *   [64KB,   128KB)         隐藏主卷头        ← 本类写：nativeCreateHiddenHeaders 的主头
 *   [128KB,  dataOffset)    外层卷数据区（外层文件住这里，不能碰）
 *   [dataOffset, hostSize-128KB)  隐藏卷数据区  ← 本类写：格式化隐藏 FAT
 *   [hostSize-128KB, hostSize-64KB)  外层备份头
 *   [hostSize-64KB,  hostSize)       隐藏备份头  ← 本类写：隐藏备份头
 * ```
 * 其中 dataOffset = hostSize - 128KB - hiddenSize（Format.c:131）。
 *
 * **外层写保护（恒烈定：读外层 FAT 算安全区）**：动手前先解锁外层卷、读其 FAT 算出已用
 * 数据区的物理上界（[FatFileSystem.usedDataAreaUpperBound] 换算容器绝对偏移），校验隐藏卷
 * dataOffset 落在该上界之后。落不下（外层已用空间挤占了尾部）就拒绝创建，绝不覆盖外层文件。
 *
 * 与桌面 VeraCrypt 互通是唯一判据：产物须能被桌面 VC 用隐藏卷口令打开、chkdsk 干净，且
 * 外层卷仍能用外层口令正常打开、原有文件完好。
 */
object HiddenVolumeCreator {

    /** 卷头组大小（主/备各 128KB）。 */
    private const val HEADER_GROUP = 131072L

    /** 隐藏卷头在容器内的偏移（TC_HIDDEN_VOLUME_HEADER_OFFSET = 64KB，主头组内第 2 槽）。 */
    private const val HIDDEN_HEADER_OFFSET = 64L * 1024

    /** 一个有效卷头 512B。 */
    private const val HEADER_SIZE = 512

    /** 熵种子字节数。 */
    private const val ENTROPY_BYTES = 4096

    /**
     * 在 [containerUri]（已存在的外层容器）内创建隐藏卷。
     *
     * @param outerPassword / outerPim / outerPrf / outerKeyfiles 外层卷凭据——用于解锁外层
     *        卷读 FAT 算安全区（写保护校验）。不解开外层就无法安全放隐藏卷。
     * @param hiddenPassword / hiddenPim / hiddenKeyfiles 隐藏卷的新凭据。
     * @param hiddenEa / hiddenPrf 隐藏卷加密算法 / PRF。
     * @param hiddenVolumeBytes 隐藏卷**毛尺寸**（含保留区，Format.c 语义）。实际可用数据区
     *        = 毛尺寸 - 保留区（<2MB→4096B，≥2MB→128KB），由 native 内部算。
     * @return Result.success(Unit) 或含错误（外层开不了 / 空间不够 / 会覆盖外层文件 / 头生成失败）。
     */
    fun create(
        resolver: ContentResolver,
        containerUri: Uri,
        outerPassword: ByteArray,
        outerPim: Int,
        outerPrf: Int,
        outerKeyfiles: List<ByteArray>,
        hiddenEa: Int,
        hiddenPrf: Int,
        hiddenPim: Int,
        hiddenPassword: ByteArray,
        hiddenKeyfiles: List<ByteArray>,
        hiddenVolumeBytes: Long,
    ): Result<Unit> = runCatching {
        require(NativeBridge.isAvailable) { "加密核心库未加载" }

        val hostSize = fileSize(resolver, containerUri)
        require(hostSize > 4 * HIDDEN_HEADER_OFFSET) { "外层容器过小，容不下隐藏卷" }
        require(hiddenVolumeBytes in 1 until (hostSize - 4 * HIDDEN_HEADER_OFFSET + 1)) {
            "隐藏卷尺寸非法：$hiddenVolumeBytes（外层 $hostSize）"
        }

        // 隐藏卷数据区在容器内的绝对起始（Format.c:131）。
        val hiddenDataOffset = hostSize - HEADER_GROUP - hiddenVolumeBytes
        require(hiddenDataOffset >= HEADER_GROUP) {
            "隐藏卷起始越界：$hiddenDataOffset（应 ≥ $HEADER_GROUP）"
        }

        // ---------- 写保护核心：解锁外层卷，读 FAT 算已用上界 ----------
        // 外层卷用外层口令解锁（可能是主卷头 offset 0）。只读读 FAT，不写。
        val outerEff = KeyfileMixer.apply(outerPassword, outerKeyfiles)
        val (outerEncStart, outerUsedUpperAbs) = try {
            openOuterAndMeasure(resolver, containerUri, outerEff, outerPim, outerPrf)
        } finally {
            outerEff.fill(0)
        }
        // 外层已用数据区的容器绝对上界 = 外层 encStart + 外层卷内逻辑上界。
        // 隐藏卷数据区起点必须 ≥ 此值，否则会覆盖外层已有文件 → 拒绝。
        require(hiddenDataOffset >= outerUsedUpperAbs) {
            "隐藏卷会覆盖外层卷已有文件：隐藏起点 $hiddenDataOffset < 外层已用上界 $outerUsedUpperAbs。" +
                "请缩小隐藏卷，或先清空外层卷尾部空间。"
        }
        // outerEncStart 仅用于日志/校验语义完整性，避免未使用告警。
        check(outerEncStart in 0 until hostSize)

        // ---------- 生成隐藏卷头（独立随机主密钥）----------
        val hiddenEff = KeyfileMixer.apply(hiddenPassword, hiddenKeyfiles)
        val headers = try {
            val entropy = ByteArray(ENTROPY_BYTES)
            SecureRandom().nextBytes(entropy)
            NativeBridge.seedRandom(entropy)
            entropy.fill(0)
            NativeBridge.createHiddenVolumeHeaders(
                hiddenEa, hiddenPrf, hiddenPim, hiddenEff, hostSize, hiddenVolumeBytes
            )
        } finally {
            hiddenEff.fill(0)
        } ?: throw IllegalStateException("隐藏卷头生成失败（熵不足 / 尺寸非法 / 参数错）")

        val (primary, backup) = headers
        try {
            writeHiddenVolume(
                resolver, containerUri, hostSize,
                primary, backup,
                hiddenPassword, hiddenPim, hiddenPrf, hiddenKeyfiles,
            )
        } finally {
            primary.fill(0); backup.fill(0)
        }
    }

    /**
     * 解锁外层卷（先试主卷头 offset 0，失败再试隐藏卷头——但这里明确是外层，用 offset 0），
     * 读其 FAT 算已用数据区上界，返回 (外层 encStart, 外层已用上界的容器绝对偏移)。
     *
     * 隔离资源：只读打开、读完即关，绝不与后续写隐藏卷的 channel 重叠（同文件双开只读+读写
     * 在 Android 上可行，但为稳妥这里读 FAT 阶段结束就关闭）。
     */
    private fun openOuterAndMeasure(
        resolver: ContentResolver,
        containerUri: Uri,
        outerEff: ByteArray,
        outerPim: Int,
        outerPrf: Int,
    ): Pair<Long, Long> {
        val pfd = resolver.openFileDescriptor(containerUri, "r")
            ?: throw FileNotFoundException("无法打开容器：$containerUri")
        pfd.use {
            val channel = java.io.FileInputStream(it.fileDescriptor).channel
            // 读外层主卷头 512B（外层卷头在文件起始）。
            val header = ByteArray(HEADER_SIZE)
            val hb = ByteBuffer.wrap(header)
            var pos = 0L
            while (hb.hasRemaining()) {
                val n = channel.read(hb, pos)
                if (n < 0) break
                pos += n
            }
            val volume = NativeBridge.openVolume(header, outerEff, outerPim, outerPrf)
                ?: throw SecurityException("外层卷口令 / PIM / PRF / keyfile 不正确，无法读外层 FAT 做写保护校验")
            try {
                // 写保护只对 FAT 外层卷成立（usedDataAreaUpperBound 目前只有 FAT 实现能保守算出
                // 已用上界）。exFAT / NTFS 外层的已用区分布在整个数据区、含尾部隐藏卷选址处，
                // 若按 FAT 解析会把已用上界误算成数据区起点 → 写保护形同虚设 → 隐藏卷覆盖外层
                // 真实文件（不可逆损毁）。故非 FAT 外层一律拒绝创建隐藏卷，绝不冒险。
                val outerBoot = VolumeReader(channel, volume).read(0, 512)
                if (ExFatBoot.isExFat(outerBoot)) {
                    throw UnsupportedOperationException("外层是 exFAT 卷，暂不支持在其中创建隐藏卷（写保护尚未覆盖 exFAT）")
                }
                if (NtfsBoot.isNtfs(outerBoot)) {
                    throw UnsupportedOperationException("外层是 NTFS 卷，暂不支持在其中创建隐藏卷（写保护尚未覆盖 NTFS）")
                }
                val fs = FatFileSystem.mount(VolumeReader(channel, volume))
                val encStart = volume.encryptedAreaStart
                // FatFileSystem 返回的是卷内逻辑偏移（0 = 外层数据区首字节）。
                // 换算容器绝对偏移 = 外层 encStart + 逻辑上界。
                val usedUpperLogical = fs.usedDataAreaUpperBound()
                val usedUpperAbs = encStart + usedUpperLogical
                return encStart to usedUpperAbs
            } finally {
                volume.close()
            }
        }
    }

    /**
     * 写隐藏卷头（主头@64KB、备份头@hostSize-64KB），开隐藏卷，格式化隐藏 FAT。
     * 只碰隐藏卷头槽和隐藏数据区，绝不动外层主头(0)/外层数据区/外层备份头。
     */
    private fun writeHiddenVolume(
        resolver: ContentResolver,
        containerUri: Uri,
        hostSize: Long,
        primary: ByteArray,
        backup: ByteArray,
        hiddenPassword: ByteArray,
        hiddenPim: Int,
        hiddenPrf: Int,
        hiddenKeyfiles: List<ByteArray>,
    ) {
        val pfd = resolver.openFileDescriptor(containerUri, "rw")
            ?: throw FileNotFoundException("无法以可写方式打开容器（需已授予写权限）")

        var raf: RandomAccessFile? = null
        var reader: VolumeReader? = null
        try {
            raf = RandomAccessFile("/proc/self/fd/${pfd.fd}", "rw")
            val channel: FileChannel = raf.channel

            // 隐藏主头 → offset 64KB；隐藏备份头 → hostSize-64KB。
            writeAbsolute(channel, HIDDEN_HEADER_OFFSET, primary, HEADER_SIZE)
            writeAbsolute(channel, hostSize - HIDDEN_HEADER_OFFSET, backup, HEADER_SIZE)
            runCatching { channel.force(false) }

            // 开隐藏卷：读隐藏主头 512B，用隐藏口令派生密钥。
            val hiddenEff = KeyfileMixer.apply(hiddenPassword, hiddenKeyfiles)
            val volume = try {
                val header = primary.copyOf(HEADER_SIZE)
                NativeBridge.openVolume(header, hiddenEff, hiddenPim, hiddenPrf)
            } finally {
                hiddenEff.fill(0)
            } ?: throw IllegalStateException("隐藏卷写头后开卷失败（头与口令 / PRF 不匹配）")

            reader = VolumeReader(channel, volume)
            // 隐藏卷数据区大小 = volume.volumeSize（native 头里已是扣掉保留区的 dataAreaSize）。
            val hiddenDataSize = volume.volumeSize
            val img = FatFormatter.buildEmptyFat(hiddenDataSize)
            for ((logicalOffset, bytes) in img.sectors) {
                if (bytes.isEmpty()) continue
                if (logicalOffset < 0 || logicalOffset + bytes.size > hiddenDataSize) {
                    throw IllegalStateException(
                        "隐藏 FAT 段越界：off=$logicalOffset len=${bytes.size} 超出隐藏数据区 $hiddenDataSize"
                    )
                }
                reader.write(logicalOffset, bytes, 0, bytes.size)
            }
            reader.flush()
        } finally {
            runCatching { reader?.close() }
            runCatching { raf?.close() }
            runCatching { pfd.close() }
        }
    }

    private fun writeAbsolute(channel: FileChannel, offset: Long, src: ByteArray, length: Int) {
        val bb = ByteBuffer.wrap(src, 0, length)
        var pos = offset
        while (bb.hasRemaining()) {
            val n = channel.write(bb, pos)
            if (n < 0) throw java.io.IOException("写隐藏卷头到偏移 $offset 失败（channel 返回 $n）")
            pos += n
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
