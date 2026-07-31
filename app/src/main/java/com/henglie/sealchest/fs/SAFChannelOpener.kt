package com.henglie.sealchest.fs

import android.content.ContentResolver
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock

/**
 * SAF 文件描述符 → [FileChannel] 工厂。
 *
 * 不再走 `/proc/self/fd/<N>` 路径——Android 10+ 真机 SELinux 禁止重开 SAF fd 的 proc 映射。
 * 改用 [FileInputStream] / [FileOutputStream] 直接从 [java.io.FileDescriptor] 取 channel，
 * 读写分别走 dup 出来的独立 fd，共享内核文件位置（同一 open file description）。
 *
 * [ReadWriteFileChannel] 是双向 FileChannel 委托:读→readChannel, 写→writeChannel。
 */
object SAFChannelOpener {

    /** 从 SAF URI 打开读写 FileChannel。失败抛异常。 */
    fun openReadWrite(resolver: ContentResolver, uri: Uri): FileChannel {
        val pfd = resolver.openFileDescriptor(uri, "rw")
            ?: throw java.io.FileNotFoundException("无法打开 SAF 描述符: $uri")

        // dup 两份独立 fd 给读写通道。两份 fd 的 position、truncate 互相同步(共享内核 open file description)。
        val readPfd = pfd.dup()
        val writePfd = pfd.dup()
        pfd.close()  // 只用 dup，原 PFD 不再需要

        val readChannel = FileInputStream(readPfd.fileDescriptor).channel
        val writeChannel = FileOutputStream(writePfd.fileDescriptor).channel
        return ReadWriteFileChannel(readChannel, writeChannel)
    }

    /** 从 SAF URI 打开只写 FileChannel（用于预分配 / truncate）。 */
    fun openWriteOnly(resolver: ContentResolver, uri: Uri): FileChannel {
        val pfd = resolver.openFileDescriptor(uri, "w")
            ?: throw java.io.FileNotFoundException("无法打开 SAF 描述符: $uri")
        return FileOutputStream(pfd.fileDescriptor).channel
    }
}

/**
 * 双向 [FileChannel]:读操作委托 [readChannel],写操作委托 [writeChannel]。
 * position / size 读 readChannel(两者共享 fd 位置,一致)。[close] 关两者。
 */
private class ReadWriteFileChannel(
    private val readChannel: FileChannel,
    private val writeChannel: FileChannel,
) : FileChannel() {
    // ---- read ----
    override fun read(dst: ByteBuffer) = readChannel.read(dst)
    override fun read(dsts: Array<out ByteBuffer>, offset: Int, length: Int) = readChannel.read(dsts, offset, length)
    override fun read(dst: ByteBuffer, position: Long) = readChannel.read(dst, position)

    // ---- write ----
    override fun write(src: ByteBuffer) = writeChannel.write(src)
    override fun write(srcs: Array<out ByteBuffer>, offset: Int, length: Int) = writeChannel.write(srcs, offset, length)
    override fun write(src: ByteBuffer, position: Long) = writeChannel.write(src, position)

    // ---- position / size ----
    override fun position() = readChannel.position()
    override fun position(newPosition: Long): FileChannel {
        readChannel.position(newPosition)
        writeChannel.position(newPosition)
        return this
    }
    override fun size() = readChannel.size()

    // ---- truncate / force ----
    override fun truncate(size: Long): FileChannel {
        writeChannel.truncate(size)
        return this
    }
    override fun force(metaData: Boolean) { writeChannel.force(metaData) }

    // ---- close ----
    override fun implCloseChannel() {
        try { readChannel.close() } finally { writeChannel.close() }
    }

    // ---- transfer ----
    override fun transferTo(position: Long, count: Long, target: java.nio.channels.WritableByteChannel) =
        readChannel.transferTo(position, count, target)
    override fun transferFrom(src: java.nio.channels.ReadableByteChannel, position: Long, count: Long) =
        writeChannel.transferFrom(src, position, count)

    // ---- unsupported for SAF ----
    override fun map(mode: MapMode, position: Long, size: Long) =
        throw UnsupportedOperationException("mmap 不支持 SAF 文件描述符")
    override fun lock(position: Long, size: Long, shared: Boolean): FileLock =
        writeChannel.lock(position, size, shared)
    override fun tryLock(position: Long, size: Long, shared: Boolean): FileLock? =
        writeChannel.tryLock(position, size, shared)
}
