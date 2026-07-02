package com.henglie.sealchest.fs

import android.content.Context
import android.net.Uri
import com.henglie.sealchest.crypto.NativeBridge
import java.io.Closeable
import java.io.FileNotFoundException
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
     * 一次挂载：持有底层 PFD / channel / 解密 reader / FAT 文件系统。
     * [close] 释放全部资源并销毁密钥。
     */
    class Mount internal constructor(
        val mountId: Long,
        val displayName: String,
        private val pfd: android.os.ParcelFileDescriptor,
        private val reader: VolumeReader,
        val fs: FatFileSystem,
    ) : Closeable {
        @Volatile
        var closed: Boolean = false
            private set

        override fun close() {
            if (closed) return
            closed = true
            // 先关 reader（销毁密钥 + 清缓存），再关 PFD。
            runCatching { reader.close() }
            runCatching { pfd.close() }
        }
    }

    private val lock = Any()
    private val idGen = AtomicLong(1)

    @Volatile
    private var current: Mount? = null

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
    ): Mount = synchronized(lock) {
        check(NativeBridge.isAvailable) { "加密核心库未加载" }

        val resolver = context.contentResolver
        val pfd = resolver.openFileDescriptor(uri, "r")
            ?: throw FileNotFoundException("无法打开容器：$uri")

        var reader: VolumeReader? = null
        try {
            val fis = java.io.FileInputStream(pfd.fileDescriptor)
            val channel = fis.channel

            // 读卷头 512B（VeraCrypt 卷头在文件起始）。
            val header = ByteArray(512)
            val hb = java.nio.ByteBuffer.wrap(header)
            var pos = 0L
            while (hb.hasRemaining()) {
                val n = channel.read(hb, pos)
                if (n < 0) break
                pos += n
            }

            val volume = NativeBridge.openVolume(header, password, pim, prf)
                ?: throw SecurityException("密码、PIM 或 PRF 不正确")

            reader = VolumeReader(channel, volume)
            val fs = FatFileSystem.mount(reader)

            val mount = Mount(idGen.getAndIncrement(), displayName, pfd, reader, fs)
            // 成功了才替换 + 关旧挂载。
            current?.close()
            current = mount
            return mount
        } catch (t: Throwable) {
            // 失败：清掉本次半成品，绝不动 current。
            runCatching { reader?.close() }
            runCatching { pfd.close() }
            // 抹掉本地口令副本。
            password.fill(0)
            throw t
        }
    }

    /** 上锁：关闭并清除当前挂载。销毁密钥。 */
    fun lock() = synchronized(lock) {
        current?.close()
        current = null
    }

    /** 在锁内执行 FAT 操作。Provider / UI 都经此串行化访问。未挂载返回 null。 */
    fun <R> withFs(block: (FatFileSystem) -> R): R? = synchronized(lock) {
        val m = current ?: return null
        if (m.closed) return null
        block(m.fs)
    }
}
