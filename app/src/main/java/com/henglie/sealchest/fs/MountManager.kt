package com.henglie.sealchest.fs

import android.content.Context
import android.net.Uri
import com.henglie.sealchest.core.Settings
import com.henglie.sealchest.crypto.NativeBridge
import java.io.Closeable
import java.io.FileNotFoundException
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.util.concurrent.atomic.AtomicLong

/**
 * 进程内当前挂载态的全局持有者。
 *
 * 为什么要全局单例：SAF 的 [SealchestDocumentsProvider] 与解锁 UI 活在同一进程但
 * 是相互独立的组件（Provider 由系统按需实例化，拿不到 Activity 的对象）。二者靠
 * 本单例共享同一个已解锁的卷 —— UI 负责解锁 / 上锁，Provider 只读当前挂载。
 *
 * 第一版只支持「同时挂一个容器」。再解锁会先上锁前一个。
 *
 * 线程安全：VeraCrypt 核心与 FAT 层都单线程，故所有对 [current] 的读写与实际
 * FAT 操作都同步在本对象的锁上。Provider 的并发查询被串行化 —— 只读场景够用。
 */
object MountManager {

    /**
     * 隐藏卷头在容器文件内的绝对偏移（TC_HIDDEN_VOLUME_HEADER_OFFSET = TC_VOLUME_HEADER_SIZE = 64KB）。
     * 主头开不了时用此偏移读隐藏卷头再试开，与桌面 VeraCrypt「一次解锁先主后隐」一致。
     */
    private const val HIDDEN_VOLUME_HEADER_OFFSET = 64L * 1024

    /**
     * 一次挂载：持有底层 PFD / channel / 解密 reader / FAT 文件系统。
     * [close] 释放全部资源并销毁密钥。
     */
    class Mount internal constructor(
        val mountId: Long,
        val displayName: String,
        private val pfd: android.os.ParcelFileDescriptor,
        internal val reader: VolumeReader,
        val fs: VolumeFs,
        /** 是否以可写方式挂载（PFD "rw" + 双向 channel）。只读挂载为 false。 */
        val writable: Boolean = false,
        /**
         * 可写挂载时额外持有的 [RandomAccessFile]（经 /proc/self/fd 拿到读写 channel）。
         * 它独占一个 fd，必须随挂载关闭，否则泄漏。只读挂载为 null。
         */
        private val raf: RandomAccessFile? = null,
    ) : Closeable {
        @Volatile
        var closed: Boolean = false
            private set

        // 容器元信息便捷访问（X10 信息面板）：转发底层 reader/fs 的只读快照。
        /** 加密算法编号（1=AES 2=Serpent 3=Twofish 4=Camellia 5=Kuznyechik，其余级联）。 */
        val encryptionAlgorithm: Int get() = reader.encryptionAlgorithm
        /** PRF 编号（1=SHA512 2=Whirlpool 3=SHA256 4=BLAKE2s 5=Streebog）。 */
        val prf: Int get() = reader.prf
        /** 数据区字节数（不含卷头）。 */
        val dataSize: Long get() = reader.dataSize
        /** 扇区大小（字节）。 */
        val sectorSize: Int get() = reader.sectorSize
        /** 是否隐藏卷。 */
        val isHidden: Boolean get() = reader.isHidden
        /** 文件系统类型串（如 FAT32 / exFAT）。 */
        val fsType: String get() = fs.fsType
        /** 卷标；无卷标为空串。 */
        val volumeLabel: String get() = fs.volumeLabel

        override fun close() {
            if (closed) return
            closed = true
            // 先关 reader（销毁密钥 + 清缓存），再关可写 raf（若有），最后关 PFD。
            runCatching { reader.close() }
            runCatching { raf?.close() }
            runCatching { pfd.close() }
        }
    }

    private val lock = Any()
    private val idGen = AtomicLong(1)

    @Volatile
    private var current: Mount? = null

    /**
     * 挂载状态变化回调：unlock 成功后调 true，lock 后调 false。
     * 用回调替代轮询（原 SealchestApp 每秒轮询 isMounted），实时响应 + 零 CPU 开销。
     * 在 synchronized 块内调，用 runCatching 包裹防回调异常影响主流程。
     * null = 无回调（默认）。
     */
    @Volatile
    var onMountStateChanged: ((mounted: Boolean) -> Unit)? = null

    /** 当前挂载，未挂载为 null。 */
    fun currentMount(): Mount? = current

    val isMounted: Boolean get() = current?.closed == false

    /**
     * 解锁并挂载 [uri] 指向的容器。成功替换当前挂载并返回，失败抛异常且不改变现状。
     *
     * @throws FileNotFoundException 打不开 URI
     * @throws IllegalStateException native 核心不可用
     * @throws SecurityException      密码 / PIM / PRF 不对（开卷失败）
     * @throws IllegalArgumentException 卷内不是可识别的 FAT
     */
    fun unlock(
        context: Context,
        uri: Uri,
        displayName: String,
        password: ByteArray,
        pim: Int,
        prf: Int,
        /**
         * 是否以可写方式挂载。默认 false = 只读（历史行为，零回归）。true 时 PFD 用
         * "rw" 打开，并经 [RandomAccessFile] 拿到可读写的双向 channel 交给 [VolumeReader]，
         * FAT 写方向（T3）才能把加密数据写回真实容器。UI 侧须已 take 了带写权限的 URI。
         */
        writable: Boolean = false,
        /**
         * keyfile 内容列表（每项一个 keyfile 的完整字节，已由 SAF 读入内存）。空 = 不用 keyfile。
         * 派生前经 [KeyfileMixer] 混入 [password]，与桌面 VeraCrypt 字节级一致。
         */
        keyfiles: List<ByteArray> = emptyList(),
    ): Mount = synchronized(lock) {
        check(NativeBridge.isAvailable) { "加密核心库未加载" }

        val resolver = context.contentResolver
        // 只读走 "r"；可写走 "rw"。SAF 要求 URI 已被授予对应权限（写需 FLAG_GRANT_WRITE）。
        val pfd = resolver.openFileDescriptor(uri, if (writable) "rw" else "r")
            ?: throw FileNotFoundException("无法打开容器：$uri")

        var reader: VolumeReader? = null
        var raf: RandomAccessFile? = null
        try {
            // 只读：FileInputStream.channel（只读 channel，历史路径不变）。
            // 可写：FileInputStream/OutputStream 的 channel 都是单向的，VolumeReader 需要
            //   在同一 channel 上 read+write，只能用 RandomAccessFile("rw")。它不吃 fd，
            //   经 /proc/self/fd/<fd> 路径打开这个已由 SAF 授权的描述符，拿到双向 channel。
            val channel: FileChannel = if (writable) {
                val fd = pfd.fd
                raf = RandomAccessFile("/proc/self/fd/$fd", "rw")
                raf!!.channel
            } else {
                java.io.FileInputStream(pfd.fileDescriptor).channel
            }

            // 读指定绝对偏移处的 512B 卷头（VeraCrypt 头是自包含加密块）。
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

            // keyfile 混入：无 keyfile 时 apply 返回 password 拷贝（等价原路径）。
            // effective 是混合后的有效密码，两次试开共用，最后统一抹除。
            val effective = com.henglie.sealchest.crypto.KeyfileMixer.apply(password, keyfiles)
            val volume = try {
                // 先试主卷头（偏移 0）。开不了再试隐藏卷头（偏移 TC_HIDDEN_VOLUME_HEADER_OFFSET
                // = 64KB）——同一密码/PIM/PRF/keyfile 依次试，与桌面 VeraCrypt「一次解锁先主后隐」
                // 一致。隐藏卷头解出的 cryptoInfo 的 EncryptedAreaStart/VolumeSize 自动指向隐藏
                // 数据区，VolumeReader / FAT 层无需任何改动即定位到隐藏卷。
                NativeBridge.openVolume(readHeaderAt(0L), effective, pim, prf)
                    ?: NativeBridge.openVolume(readHeaderAt(HIDDEN_VOLUME_HEADER_OFFSET), effective, pim, prf)
            } finally {
                effective.fill(0)
            } ?: run {
                // 开卷失败：先探测是不是「已知但不支持」的容器（当前仅 LUKS），给针对性
                // 提示，避免用户对着 LUKS 容器反复试 VeraCrypt 密码。只探测魔数、绝不解密。
                val raw0 = readHeaderAt(0L)
                if (ContainerFormat.isLuks(raw0)) {
                    val ver = ContainerFormat.luksVersion(raw0)
                    throw UnsupportedContainerException(
                        "检测到 LUKS" + (if (ver > 0) ver.toString() else "") + " 容器，暂不支持解锁"
                    )
                }
                throw SecurityException("密码、PIM、PRF 或 keyfile 不正确")
            }

            reader = VolumeReader(channel, volume)
            // 文件系统分发：读解密后的引导扇区（逻辑偏移 0）。exFAT 签名走 exFAT。
            // NTFS：默认仍拒绝（正常用户零影响，宁可打不开绝不挂垃圾/误写）；仅当设置里显式开启
            //   「NTFS 实验」开关才挂 NtfsFileSystem——供恒烈真机 chkdsk 验收。验收纪律见测试手册：
            //   先挂只读（本次 writable=false 时只跑读路径，零写风险）验证读；读通过再开可写验写。
            val boot0 = reader.read(0, 512)
            if (NtfsBoot.isNtfs(boot0) && !Settings.ntfsExperimental(context)) {
                throw UnsupportedContainerException("检测到 NTFS 文件系统容器，当前版本暂不支持（NTFS 读写实验开关未开启）")
            }
            val fs: VolumeFs = when {
                NtfsBoot.isNtfs(boot0) -> NtfsFileSystem.mount(reader)
                ExFatBoot.isExFat(boot0) -> ExFatFileSystem.mount(reader)
                else -> FatFileSystem.mount(reader)
            }

            val mount = Mount(idGen.getAndIncrement(), displayName, pfd, reader, fs, writable, raf)
            // 成功了才替换 + 关旧挂载。
            current?.close()
            current = mount
            // 通知系统 SAF 根变了（从无根变有根），老 DocumentsUI 才会重查看见入口。
            com.henglie.sealchest.saf.SafNotify.rootsChanged(context.applicationContext)
            // 通知挂载状态变化回调（替代 SealchestApp 轮询）。
            runCatching { onMountStateChanged?.invoke(true) }
            return mount
        } catch (t: Throwable) {
            // 失败：清掉本次半成品，绝不动 current。
            runCatching { reader?.close() }
            runCatching { raf?.close() }
            runCatching { pfd.close() }
            // 抹掉本地口令副本。
            password.fill(0)
            throw t
        }
    }

    /** 上锁：关闭并清除当前挂载。销毁密钥。[context] 用于通知 SAF 根消失。 */
    fun lock(context: Context? = null) = synchronized(lock) {
        val had = current != null
        current?.close()
        current = null
        // 通知系统根消失（从有根变无根），文件管理器里的入口随之消失。
        if (had) context?.applicationContext?.let {
            com.henglie.sealchest.saf.SafNotify.rootsChanged(it)
        }
        // 通知挂载状态变化回调（替代 SealchestApp 轮询）。
        if (had) runCatching { onMountStateChanged?.invoke(false) }
    }

    /** 在锁内执行 FAT 操作。Provider / UI 都经此串行化访问。未挂载返回 null。 */
    fun <R> withFs(block: (VolumeFs) -> R): R? = synchronized(lock) {
        val m = current ?: return null
        if (m.closed) return null
        block(m.fs)
    }

    /**
     * 写路径唯一入口：锁内执行写操作，要求当前挂载是**可写挂载**
     * （[unlock] 时 writable=true）。block 结束后统一 [VolumeReader.flush] 落盘。
     * 未挂载 / 只读挂载返回 null —— 只读挂载永不会被写入，是写权限的最后一道闸。
     *
     * 事务性：一次 block 内可连做多个结构改动（分配簇 + 写数据 + 目录项），
     * 全部完成才 flush 一次，减少半写窗口。仍非崩溃原子（二期日志/双写头）。
     */
    fun <R> withWritableFs(block: (VolumeFs) -> R): R? = synchronized(lock) {
        val m = current ?: return null
        if (m.closed || !m.writable) return null
        // M3 修复：block 抛异常时也必须 flush + invalidateFsInfo，否则已写脏页留在 channel、
        //   FSInfo 未失效 → 进程被杀后 FAT 半写、chkdsk 可能报不一致。try/finally 保证落盘收口，
        //   异常照常上抛（调用方感知失败）。flush/invalidate 各自 runCatching，互不阻断。
        try {
            block(m.fs)
        } finally {
            // 写后让 FAT32 FSInfo 空闲计数失效（置 unknown，OS 重算），避免桌面 VC/chkdsk
            // 报「空闲空间不符」。FAT12/16 或无 FSInfo 时空操作。放 flush 之前，一并落盘。
            runCatching { m.fs.invalidateFsInfo() }
            runCatching { m.reader.flush() }
        }
    }

    /** 当前挂载是否可写。UI 据此决定是否显示写操作入口。 */
    val isWritable: Boolean get() = current?.let { !it.closed && it.writable } ?: false

    /**
     * 对当前挂载卷跑加解密往返自测（见 [VolumeReader.selfTest]）。未挂载返回 null。
     * 在锁内串行执行，零风险（内存操作、不写盘），供 UI 验 encrypt 方向可用于写入。
     */
    fun selfTest(): VolumeReader.SelfTestResult? = synchronized(lock) {
        val m = current ?: return null
        if (m.closed) return null
        m.reader.selfTest()
    }

    /**
     * 在锁内执行 FAT 操作，且要求当前挂载仍是 [expectMountId]。用于跨多次调用的
     * 流式读取（如 [SealchestDocumentsProvider] 的 openDocument 后台线程）：每读一块
     * 都校验挂载没被换 / 上锁，避免读到新卷的内容或 use-after-free。
     *
     * 返回 null 有两种情况：未挂载，或当前挂载 id 已非 [expectMountId]（被换 / 已上锁）。
     * 调用方据此安全中止流。
     */
    fun <R> withMount(expectMountId: Long, block: (VolumeFs) -> R): R? = synchronized(lock) {
        val m = current ?: return null
        if (m.closed || m.mountId != expectMountId) return null
        block(m.fs)
    }

    /** 当前挂载 id，未挂载为 0。供流式读取开始时抓取基准。 */
    fun currentMountId(): Long = synchronized(lock) { current?.takeIf { !it.closed }?.mountId ?: 0L }
}
