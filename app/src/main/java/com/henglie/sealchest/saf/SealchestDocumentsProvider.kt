package com.henglie.sealchest.saf

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import com.henglie.sealchest.fs.FatFileSystem
import com.henglie.sealchest.fs.MountManager

/**
 * 把当前解锁的 FAT 卷暴露给系统 SAF（文件选择器 / 其它 app）。
 *
 * 文档 ID 语义（docId）：`路径|firstCluster|size|dir`，其中路径仅供展示 / 排错，
 * 定位靠簇号。根 docId 固定 [ROOT_DOC_ID]。这样 openDocument 无需重新遍历目录树，
 * 直接用簇号 + 大小从 [FatFileSystem] 读。
 *
 * 只读：不实现 create / delete / write。openDocument 只给 "r"。
 * 卷未挂载时 queryRoots 返回空 —— 系统不显示本源，符合"锁着看不见"。
 *
 * 明文只在本进程内存在：openDocument 把解密内容写进一对匿名管道，直接喂给调用方，
 * 不落磁盘明文。大文件用后台线程流式写，避免 ANR 与 OOM。
 */
class SealchestDocumentsProvider : DocumentsProvider() {

    private companion object {
        const val ROOT_ID = "sealchest-root"
        const val ROOT_DOC_ID = "root"

        val DEFAULT_ROOT_COLS = arrayOf(
            Root.COLUMN_ROOT_ID,
            Root.COLUMN_FLAGS,
            Root.COLUMN_TITLE,
            Root.COLUMN_DOCUMENT_ID,
            Root.COLUMN_ICON,
        )
        val DEFAULT_DOC_COLS = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_SIZE,
            Document.COLUMN_LAST_MODIFIED,
            Document.COLUMN_FLAGS,
        )

        /** 大文件流式管道阈值：超过直接开线程写，小文件同步写完即可。 */
        const val PIPE_CHUNK = 64 * 1024
    }

    override fun onCreate(): Boolean = true

    // ---------------- docId 编解码 ----------------

    private data class DocRef(
        val path: String,
        val firstCluster: Long,
        val size: Long,
        val isDir: Boolean,
    )

    private fun encode(ref: DocRef): String =
        "${ref.path}|${ref.firstCluster}|${ref.size}|${if (ref.isDir) 1 else 0}"

    private fun decode(docId: String): DocRef {
        // 根 docId 不碰 fs：listRoot 内部自判类型定位根目录，这里的 firstCluster 用不上。
        if (docId == ROOT_DOC_ID) return DocRef("", 0, 0, true)
        val parts = docId.split("|")
        require(parts.size == 4) { "非法 docId: $docId" }
        return DocRef(parts[0], parts[1].toLong(), parts[2].toLong(), parts[3] == "1")
    }

    // ---------------- roots ----------------

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val cursor = MatrixCursor(projection ?: DEFAULT_ROOT_COLS)
        val mount = MountManager.currentMount() ?: return cursor  // 未挂载：无根，SAF 里看不见
        cursor.newRow().apply {
            add(Root.COLUMN_ROOT_ID, ROOT_ID)
            // 只读、支持递归搜索关掉（第一版不做 search）。
            add(Root.COLUMN_FLAGS, 0)
            add(Root.COLUMN_TITLE, mount.displayName)
            add(Root.COLUMN_DOCUMENT_ID, ROOT_DOC_ID)
            add(Root.COLUMN_ICON, com.henglie.sealchest.R.mipmap.ic_launcher)
        }
        return cursor
    }

    // ---------------- documents ----------------

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val cursor = MatrixCursor(projection ?: DEFAULT_DOC_COLS)
        val ref = decode(documentId)
        if (documentId == ROOT_DOC_ID) {
            val mount = MountManager.currentMount() ?: throw java.io.FileNotFoundException("未挂载")
            addRow(cursor, ROOT_DOC_ID, mount.displayName, 0, true, 0)
        } else {
            val name = ref.path.substringAfterLast('/')
            addRow(cursor, documentId, name, ref.size, ref.isDir, 0)
        }
        return cursor
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val cursor = MatrixCursor(projection ?: DEFAULT_DOC_COLS)
        val parent = decode(parentDocumentId)

        // 列目录整段在 MountManager 锁内完成：VeraCrypt 核心单线程 + VolumeReader
        // 缓存非线程安全，Provider 又会被系统并发拉起，必须串行化。
        val entries = MountManager.withFs { fs ->
            if (parentDocumentId == ROOT_DOC_ID || parent.path.isEmpty()) fs.listRoot()
            else fs.listDir(parent.firstCluster)
        } ?: throw java.io.FileNotFoundException("容器未挂载或已锁定")

        val parentPath = if (parentDocumentId == ROOT_DOC_ID) "" else parent.path
        for (e in entries) {
            val childPath = if (parentPath.isEmpty()) e.name else "$parentPath/${e.name}"
            val childId = encode(DocRef(childPath, e.firstCluster, e.size, e.isDirectory))
            addRow(cursor, childId, e.name, e.size, e.isDirectory, e.lastModified)
        }
        return cursor
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        if (mode != "r") throw UnsupportedOperationException("只读，不支持写入模式: $mode")
        val ref = decode(documentId)
        if (ref.isDir) throw java.io.FileNotFoundException("目录不能作为文件打开")

        // 抓取当前挂载 id 作基准：后台线程每读一块都校验挂载没被换 / 上锁。
        // 打开时就没挂载则直接失败。
        val mountId = MountManager.currentMountId()
        if (mountId == 0L) throw java.io.FileNotFoundException("容器未挂载或已锁定")

        val pipe = ParcelFileDescriptor.createReliablePipe()
        val readSide = pipe[0]
        val writeSide = pipe[1]

        // 后台线程流式解密 + 写入管道，避免大文件阻塞 / OOM。
        // 每块读取经 MountManager.withMount 进锁 + 校验挂载 id：用户中途上锁 /
        // 换卷时，withMount 返回 null，循环安全中止（不会 use-after-free，也不会
        // 把新卷内容混进旧文件流）。
        Thread({
            ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use { os ->
                try {
                    var pos = 0L
                    while (pos < ref.size) {
                        if (signal?.isCanceled == true) break
                        val want = minOf(PIPE_CHUNK.toLong(), ref.size - pos).toInt()
                        val chunk = MountManager.withMount(mountId) { fs ->
                            fs.readFile(ref.firstCluster, ref.size, pos, want)
                        } ?: break   // 挂载已变 / 上锁：安全中止流
                        if (chunk.isEmpty()) break
                        os.write(chunk)
                        pos += chunk.size
                    }
                    os.flush()
                } catch (_: Throwable) {
                    // 读取端会因管道提前关闭收到 IOException，交由其处理。
                }
            }
        }, "sc-open-$documentId").start()

        return readSide
    }

    override fun getDocumentType(documentId: String): String {
        val ref = decode(documentId)
        return if (ref.isDir) Document.MIME_TYPE_DIR else mimeOf(ref.path)
    }

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        if (parentDocumentId == ROOT_DOC_ID) return true
        val parent = decode(parentDocumentId)
        val child = decode(documentId)
        return child.path.startsWith(if (parent.path.isEmpty()) "" else "${parent.path}/")
    }

    // ---------------- helpers ----------------

    private fun addRow(
        cursor: MatrixCursor,
        docId: String,
        name: String,
        size: Long,
        isDir: Boolean,
        mtime: Long,
    ) {
        cursor.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID, docId)
            add(Document.COLUMN_DISPLAY_NAME, name)
            add(Document.COLUMN_MIME_TYPE, if (isDir) Document.MIME_TYPE_DIR else mimeOf(name))
            add(Document.COLUMN_SIZE, size)
            add(Document.COLUMN_LAST_MODIFIED, if (mtime > 0) mtime else null)
            // 只读：不给 SUPPORTS_WRITE / DELETE / REMOVE 任何写标志。
            add(Document.COLUMN_FLAGS, 0)
        }
    }

    /** 按扩展名粗判 MIME；认不出给 application/octet-stream。 */
    private fun mimeOf(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return when (ext) {
            "txt", "log", "ini", "cfg", "md" -> "text/plain"
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "webp" -> "image/webp"
            "pdf" -> "application/pdf"
            "zip" -> "application/zip"
            "mp3" -> "audio/mpeg"
            "mp4" -> "video/mp4"
            "json" -> "application/json"
            "xml" -> "application/xml"
            "html", "htm" -> "text/html"
            "csv" -> "text/csv"
            "doc", "docx" -> "application/msword"
            "xls", "xlsx" -> "application/vnd.ms-excel"
            else -> "application/octet-stream"
        }
    }
}
