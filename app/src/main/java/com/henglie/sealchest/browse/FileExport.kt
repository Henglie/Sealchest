package com.henglie.sealchest.browse

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import com.henglie.sealchest.fs.MountManager
import java.io.File
import java.io.FileOutputStream

/**
 * 把容器内文件导出到进程私有缓存，再经 [FileProvider] 生成可跨进程共享的 content URI。
 *
 * 为什么要落缓存：Android 的「用其它应用打开 / 分享」需要一个别的 app 能读的 URI。
 * 我们的 SAF Provider 虽也能给 URI，但那条路径要求对方 app 懂 DocumentsContract；
 * 直接 FileProvider 一个真实文件最通用。代价是明文短暂落盘 —— 放 cacheDir 的
 * 专用子目录，上锁 / 退出时整目录清掉（见 [clearExportCache]）。
 *
 * 明文落盘是安全权衡：取证 / 查看场景要能把文件交给系统看图、看 PDF 的 app，
 * 无法全程只在内存。用户若极端敏感，应避免「用其它应用打开」，只用内置预览。
 */
object FileExport {

    /** 缓存子目录名，与 file_paths.xml 的 <cache-path name> 对应。 */
    private const val EXPORT_DIR = "export"

    /** FileProvider authority，与 Manifest 一致。 */
    private fun authority(context: Context) = context.packageName + ".fileprovider"

    /**
     * 把容器内 [firstCluster]/[size] 指向的文件解密写到缓存文件，返回其 [File]。
     * 失败（未挂载 / 读空）返回 null。[displayName] 用作缓存文件名（清洗非法字符）。
     */
    fun exportToCache(context: Context, displayName: String, firstCluster: Long, size: Long): File? {
        val dir = File(context.cacheDir, EXPORT_DIR).apply { mkdirs() }
        val safeName = displayName.replace(Regex("[^\\p{L}\\p{N}._-]"), "_").ifBlank { "file" }
        val out = File(dir, safeName)

        val ok = try {
            FileOutputStream(out).use { fos ->
                var pos = 0L
                val chunkSize = 64 * 1024
                while (pos < size) {
                    val want = minOf(chunkSize.toLong(), size - pos).toInt()
                    val chunk = MountManager.withFs { fs ->
                        fs.readFile(firstCluster, size, pos, want)
                    } ?: return null   // 未挂载 / 已上锁
                    if (chunk.isEmpty()) break
                    fos.write(chunk)
                    pos += chunk.size
                }
                fos.flush()
                true
            }
        } catch (_: Throwable) {
            false
        }
        return if (ok) out else null
    }

    /** 生成缓存文件的 FileProvider content URI。 */
    fun uriFor(context: Context, file: File): Uri =
        FileProvider.getUriForFile(context, authority(context), file)

    /**
     * 构造「用其它应用打开」的 Intent（ACTION_VIEW）。调用方 startActivity。
     * 授予对方临时读权限。
     */
    fun openWithIntent(context: Context, file: File, mime: String): Intent =
        Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uriFor(context, file), mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

    /** 构造「分享」的 Intent（ACTION_SEND）。 */
    fun shareIntent(context: Context, file: File, mime: String): Intent =
        Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uriFor(context, file))
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

    /** 清空导出缓存目录里的明文。上锁 / 退出时调用。 */
    fun clearExportCache(context: Context) {
        val dir = File(context.cacheDir, EXPORT_DIR)
        runCatching { dir.listFiles()?.forEach { it.delete() } }
    }
}
