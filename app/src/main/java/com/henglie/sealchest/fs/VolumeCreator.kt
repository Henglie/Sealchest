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
 * 卷创建编排层（B2：创建新 VeraCrypt 容器）。
 *
 * 与 [MountManager]（解锁/挂载已有卷）对称：这里负责把一个「已由 SAF 授权可写、
 * 且已预分配到目标总大小的空文件」写成一个可被桌面 VeraCrypt 打开的合法容器。
 *
 * 全流程严格按序，任一步失败即中止并返回 [Result.failure]，绝不留半成品静默成功。
 * 加解密核心全走 native（官方实现），本层只做编排、偏移计算与资源管理。
 *
 * 文件布局（VeraCrypt 标准卷，非隐藏）：
 *   [ 主头组 128KB ][ 数据区 volumeSizeBytes ][ 备份头组 128KB ]
 *   偏移 0            偏移 131072              偏移 (总大小 - 131072)
 *   文件总大小 = 131072 + volumeSizeBytes + 131072 = volumeSizeBytes + 262144
 *
 * 卷头（主/备份各 512B）是 native 已经加密好的原始字节，直接明文写到 channel 绝对
 * 偏移，不再过 XTS。数据区才是 XTS 密文，经 [VolumeReader] 的 encrypt 写回。
 */
object VolumeCreator {

    /** VeraCrypt 头组大小：主头组 128KB，备份头组 128KB。 */
    private const val HEADER_AREA_SIZE = 131072L

    /** 单个卷头字节数（salt + 加密头），VeraCrypt 固定 512。 */
    private const val HEADER_SIZE = 512

    /** 数据区最小合理下限：256KB（足够放下一个最小 FAT 结构 + 冗余）。 */
    private const val MIN_DATA_SIZE = 256L * 1024

    /** 灌给 native 随机池的熵字节数。4096B 远超一次头生成所需（主密钥 + salt + …）。 */
    private const val ENTROPY_BYTES = 4096

    private const val UNIT = NativeBridge.UNIT_SIZE.toLong()   // 512

    /**
     * 在 [containerUri]（已由 SAF 授予写权限、且已预分配到目标总大小的空文件）创建
     * 新 VeraCrypt 容器。
     *
     * @param volumeSizeBytes 数据区大小（不含两侧头组），必须 512 对齐且 ≥ [MIN_DATA_SIZE]。
     *        文件真实总大小须为 volumeSizeBytes + 262144，调用方预分配时按此。
     * @return [Result.success] 表示容器已写成且可开卷；失败带原因，且不保证文件内容完整
     *         （调用方失败后应删除该半成品文件）。
     */
    fun create(
        resolver: ContentResolver,
        containerUri: Uri,
        ea: Int,
        prf: Int,
        pim: Int,
        password: ByteArray,
        keyfiles: List<ByteArray>,
        volumeSizeBytes: Long,
        fsType: Int = 0,
        clusterSize: Int = 0,
        dynamic: Boolean = false,
    ): Result<Unit> {
        // ---------- 1. 参数校验 ----------
        if (!NativeBridge.isAvailable) {
            return Result.failure(IllegalStateException("加密核心库未加载"))
        }
        if (volumeSizeBytes < MIN_DATA_SIZE) {
            return Result.failure(
                IllegalArgumentException("数据区过小：$volumeSizeBytes < 最小 $MIN_DATA_SIZE")
            )
        }
        if (volumeSizeBytes % UNIT != 0L) {
            return Result.failure(
                IllegalArgumentException("数据区大小须 512 对齐：$volumeSizeBytes")
            )
        }
        if (pim < 0) {
            return Result.failure(IllegalArgumentException("PIM 不能为负：$pim"))
        }
        // X2：文件系统目前仅支持 FAT(0)，exFAT(1) / NTFS(2) 后端 Formatter 未就绪。
        // UI 侧已对未就绪项灰显，此处兜底拦截，防止误传。
        if (fsType != 0) {
            return Result.failure(
                IllegalArgumentException("暂不支持该文件系统创建：fsType=$fsType（目前仅 FAT）")
            )
        }
        // X2：dynamic（稀疏卷）UI 已备，后端稀疏实现待接，暂当普通卷处理。
        // 此处收下标志不使用，待后端实现稀疏分配后接入。
        if (dynamic) {
            // 故意不报错：UI 已勾选，后端按普通卷创建仍能产出合法容器。
        }
        // ea / prf 合法性：本层不硬编码算法枚举（那属 native 常量域），交由 native
        // createVolumeHeaders 校验并在非法时返回 null。此处只挡明显越界。
        // TODO(契约): 若主开发在 NativeBridge 暴露了 ea/prf 合法枚举集，可在此提前校验，
        //             给出比「头生成失败」更友好的错误。

        val totalSize = volumeSizeBytes + HEADER_AREA_SIZE * 2
        val backupHeaderOffset = totalSize - HEADER_AREA_SIZE   // = volumeSizeBytes + 131072

        // ---------- 2. keyfile 混入 ----------
        // 无 keyfile 时 apply 返回 password 的拷贝（等价原密码），故 eff 始终是独立数组，
        // 用完必须 fill(0)。原 password 的生命周期归调用方，本层不动它。
        val eff: ByteArray = try {
            KeyfileMixer.apply(password, keyfiles)
        } catch (t: Throwable) {
            return Result.failure(t)
        }

        var entropy: ByteArray? = null
        try {
            // ---------- 3. 生成熵并灌入 native 随机池 ----------
            entropy = ByteArray(ENTROPY_BYTES)
            SecureRandom().nextBytes(entropy)
            // TODO(契约): NativeBridge.seedRandom(entropy: ByteArray) 由主开发新增。
            //             语义：把这些字节混入 native RNG 池（RandomNumberGenerator），
            //             供后续 CreateVolumeHeaderInMemory 取主密钥 / salt。
            NativeBridge.seedRandom(entropy)

            // ---------- 4. native 生成主头 + 备份头（共享同一随机主密钥）----------
            // TODO(契约): NativeBridge.createVolumeHeaders(
            //               ea, prf, pim, password, volumeSize, encStart
            //             ): Pair<ByteArray, ByteArray>?  由主开发新增。
            //   - volumeSize = 数据区字节数（不含头组）= volumeSizeBytes
            //   - encStart   = 数据区在文件中的起始偏移 = 131072（主头组之后）
            //   - 返回 (主头512B, 备份头512B)，两头共享随机主密钥，仅头本身盐/位置不同；
            //     失败返回 null（参数非法 / RNG 未就绪 / 算法不支持）。
            //   若签名微调（如需 sectorSize 参数或返回值含更多元数据），在此适配。
            val headers = NativeBridge.createVolumeHeaders(
                ea, prf, pim, eff, volumeSizeBytes, HEADER_AREA_SIZE
            ) ?: return Result.failure(IllegalStateException("native 生成卷头失败"))

            val primary = headers.first
            val backup = headers.second
            if (primary.size < HEADER_SIZE || backup.size < HEADER_SIZE) {
                return Result.failure(
                    IllegalStateException(
                        "卷头长度非法：primary=${primary.size} backup=${backup.size}，须 ≥ $HEADER_SIZE"
                    )
                )
            }

            // ---------- 5~9. 打开可写 channel，写头 + 开卷 + 写 FAT ----------
            return writeContainer(
                resolver = resolver,
                containerUri = containerUri,
                eff = eff,
                pim = pim,
                prf = prf,
                primary = primary,
                backup = backup,
                backupHeaderOffset = backupHeaderOffset,
                volumeSizeBytes = volumeSizeBytes,
                clusterSize = clusterSize,
            )
        } catch (t: Throwable) {
            return Result.failure(t)
        } finally {
            // 敏感数据抹除：eff（有效密码）与 entropy（随机池种子）。
            eff.fill(0)
            entropy?.fill(0)
        }
    }

    /**
     * 打开可写 channel，落主/备份头（明文原始写），再开卷写空 FAT。
     * 独立成函数是为了把 channel/pfd/volume/reader 的资源释放集中在一处 finally。
     */
    private fun writeContainer(
        resolver: ContentResolver,
        containerUri: Uri,
        eff: ByteArray,
        pim: Int,
        prf: Int,
        primary: ByteArray,
        backup: ByteArray,
        backupHeaderOffset: Long,
        volumeSizeBytes: Long,
        clusterSize: Int = 0,
    ): Result<Unit> {
        // 可写打开：SAF 要求 URI 已被授予 FLAG_GRANT_WRITE。
        val pfd = resolver.openFileDescriptor(containerUri, "rw")
            ?: return Result.failure(FileNotFoundException("无法打开容器：$containerUri"))

        var raf: RandomAccessFile? = null
        var reader: VolumeReader? = null
        try {
            // 双向 channel：FileInputStream/OutputStream 的 channel 是单向的，
            // VolumeReader 需要在同一 channel 上 read+write，只能用 RandomAccessFile("rw")。
            // 它不吃 fd，经 /proc/self/fd/<fd> 打开这个已由 SAF 授权的描述符拿双向 channel。
            // （手法与 MountManager.unlock 可写路径一致。）
            val fd = pfd.fd
            raf = RandomAccessFile("/proc/self/fd/$fd", "rw")
            val channel: FileChannel = raf.channel

            // ---------- 5. 写主头（偏移 0）与备份头（偏移 backupHeaderOffset）----------
            // 卷头是 native 已加密好的原始字节，直接明文写绝对偏移，不再过 XTS。
            // 只写前 512B（headers 数组可能更长，多余部分忽略）。
            writeAbsolute(channel, 0L, primary, HEADER_SIZE)
            writeAbsolute(channel, backupHeaderOffset, backup, HEADER_SIZE)
            // 让头先落盘，避免后续开卷时读到旧内容（同一 channel 理论上可见，force 求稳）。
            runCatching { channel.force(false) }

            // ---------- 6. 用 eff 开卷，拿 VolumeReader ----------
            // openVolume 读主头 512B 验密码 + 派生密钥。这里用刚写下的 primary（原始字节）。
            val header = primary.copyOf(HEADER_SIZE)
            val volume = NativeBridge.openVolume(header, eff, pim, prf)
                ?: return Result.failure(
                    IllegalStateException("新建后开卷失败：头与密码/PRF 不匹配（native 生成头有误？）")
                )
            reader = VolumeReader(channel, volume)

            // ---------- 7. 数据区随机填充：基础版方案选择 ----------
            // VeraCrypt 语义：整个数据区应是「加密后的随机数据」，明文不可与随机区分。
            //
            // 严格实现应在写 FAT 前，把整个数据区用随机明文经 XTS 加密铺满（reader.write
            // 随机字节），使未用扇区也是高熵密文。
            //
            // 基础版选择【不做全区随机填充，只写 FAT 结构，其余留零】。权衡：
            //   优点：一次创建只写 FAT 的几十 KB，避免对整卷做 read-modify-write（那会
            //         对每个 512B 单元 decrypt+encrypt+回写，GB 级容器耗时/耗电不可接受）。
            //   代价（安全）：未写扇区是「加密后的全零」。XTS 下全零明文的密文并非全零，
            //         但对同一密钥、随扇区号变化 —— 攻击者虽拿不到明文，却可能从密文的
            //         统计特征区分「已用（FAT/文件数据）」与「从未写过（全零明文）」区域，
            //         泄漏容器使用量这一元信息。对「整卷不可区分」的强隐私目标是弱化。
            //   不影响：能否被桌面 VeraCrypt 正常打开、挂载、读写 —— 全零数据区是合法的
            //         空文件系统底衬，功能完全正常。
            // TODO(增强): 后续版本加「创建时全区随机填充」开关：分块（如 1MB）生成随机
            //             明文 → reader.write 铺满数据区 → 再覆盖写 FAT 结构。可加进度回调。

            // ---------- 8. 写空 FAT 结构 ----------
            // TODO(契约): FatFormatter.buildEmptyFat(volumeSizeBytes) 由另一位辅开发提供。
            //   返回 FatImage(bytesPerSector, sectors: List<Pair<卷内逻辑偏移, 字节段>>)，
            //   逻辑偏移 0 = 数据区首字节。这里只消费逻辑偏移与字节段，逐段 reader.write。
            val img = FatFormatter.buildEmptyFat(volumeSizeBytes, clusterSize)
            for ((logicalOffset, bytes) in img.sectors) {
                if (bytes.isEmpty()) continue
                // 防御：FAT 段不得越过数据区尾（否则会写进/越过备份头区，破坏容器）。
                if (logicalOffset < 0 || logicalOffset + bytes.size > volumeSizeBytes) {
                    return Result.failure(
                        IllegalStateException(
                            "FAT 段越界：off=$logicalOffset len=${bytes.size} 超出数据区 $volumeSizeBytes"
                        )
                    )
                }
                reader.write(logicalOffset, bytes, 0, bytes.size)
            }

            // ---------- 9. 落盘 ----------
            reader.flush()
            return Result.success(Unit)
        } catch (t: Throwable) {
            return Result.failure(t)
        } finally {
            // 释放顺序：先 reader（销毁密钥 + 清缓存），再 raf（独占 fd），最后 pfd。
            runCatching { reader?.close() }
            runCatching { raf?.close() }
            runCatching { pfd.close() }
        }
    }

    /** 向 channel 的绝对偏移 [offset] 写 [src] 的前 [length] 字节，写满或报错才返回。 */
    private fun writeAbsolute(channel: FileChannel, offset: Long, src: ByteArray, length: Int) {
        val bb = ByteBuffer.wrap(src, 0, length)
        var pos = offset
        while (bb.hasRemaining()) {
            val n = channel.write(bb, pos)
            if (n < 0) throw java.io.IOException("写卷头到偏移 $offset 失败（channel 返回 $n）")
            pos += n
        }
    }
}
