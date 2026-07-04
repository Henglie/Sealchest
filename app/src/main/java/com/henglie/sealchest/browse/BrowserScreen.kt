package com.henglie.sealchest.browse

import android.graphics.BitmapFactory
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.henglie.sealchest.R
import com.henglie.sealchest.fs.FatFileSystem
import com.henglie.sealchest.fs.MountManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 内置文件浏览器：不依赖系统 DocumentsUI，自己遍历 + 预览 + 导出。
 *
 * 为什么要内置：老安卓（7/9）自带文件管理器多半不认第三方 SAF Provider，
 * 用户在那种机器上「看不见容器入口」。内置浏览器让任何 Android 版本都能直接
 * 在匿匣内浏览、预览、导出容器文件，SAF 作为「额外」暴露而非唯一入口。
 *
 * 竞品（EDS / VaultExplorer / CryptoContainer）都有内置浏览器 —— 这是必备能力。
 *
 * 导航：维护一个目录栈（[DirFrame] 列表），栈顶是当前目录。进目录压栈，返回弹栈。
 * 预览：图片 / 文本内嵌；其它类型走「用其它应用打开」（经 FileProvider）。
 */

/** 目录栈的一层：显示名 + 该目录首簇。根目录 isRoot=true，firstCluster 由 fs.listRoot 内部处理。 */
private data class DirFrame(val name: String, val firstCluster: Long, val isRoot: Boolean)

/** 当前预览态。 */
private sealed interface Preview {
    data class ImagePreview(val name: String, val bytes: ByteArray) : Preview
    data class TextPreview(val name: String, val text: String) : Preview
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrowserScreen(onExit: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val dirStack = remember { mutableStateListOf(DirFrame("", -1L, true)) }
    val current = dirStack.last()

    var entries by remember { mutableStateOf<List<FatFileSystem.Entry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var selected by remember { mutableStateOf<FatFileSystem.Entry?>(null) }
    var preview by remember { mutableStateOf<Preview?>(null) }
    var exportTarget by remember { mutableStateOf<FatFileSystem.Entry?>(null) }

    // 载入当前目录内容。current 变即重载。
    LaunchedEffect(current.firstCluster, current.isRoot) {
        loading = true
        val list = withContext(Dispatchers.IO) {
            MountManager.withFs { fs ->
                if (current.isRoot) fs.listRoot() else fs.listDir(current.firstCluster)
            } ?: emptyList()
        }
        // 文件夹在前，各自按名排序。
        entries = list.sortedWith(
            compareByDescending<FatFileSystem.Entry> { it.isDirectory }
                .thenBy { it.name.lowercase() }
        )
        loading = false
    }

    // 导出目标选定后，用 SAF 创建文档并写入。
    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        val target = exportTarget
        exportTarget = null
        if (uri != null && target != null) {
            scope.launch {
                val ok = withContext(Dispatchers.IO) {
                    runCatching {
                        context.contentResolver.openOutputStream(uri)?.use { os ->
                            var pos = 0L
                            while (pos < target.size) {
                                val want = minOf(64 * 1024L, target.size - pos).toInt()
                                val chunk = MountManager.withFs { fs ->
                                    fs.readFile(target.firstCluster, target.size, pos, want)
                                } ?: break
                                if (chunk.isEmpty()) break
                                os.write(chunk)
                                pos += chunk.size
                            }
                            os.flush()
                        }
                        true
                    }.getOrDefault(false)
                }
                Toast.makeText(
                    context,
                    if (ok) context.getString(R.string.browse_exported, target.name)
                    else context.getString(R.string.browse_export_failed),
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    BackHandler(enabled = dirStack.size > 1) {
        dirStack.removeAt(dirStack.lastIndex)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    val title = if (current.isRoot) stringResource(R.string.browse_root) else current.name
                    Text(title, maxLines = 1)
                },
                navigationIcon = {
                    IconButton(onClick = {
                        if (dirStack.size > 1) dirStack.removeAt(dirStack.lastIndex) else onExit()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.browse_back))
                    }
                },
            )
        },
    ) { inner ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(inner)
        ) {
            if (loading) {
                CircularProgressIndicator(Modifier.align(Alignment.Center))
            } else if (entries.isEmpty()) {
                Text(stringResource(R.string.browse_empty), Modifier.align(Alignment.Center))
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(entries) { e ->
                        EntryRow(e) {
                            if (e.isDirectory) {
                                dirStack.add(DirFrame(e.name, e.firstCluster, false))
                            } else {
                                selected = e
                            }
                        }
                    }
                }
            }
        }
    }

    // 文件动作单
    selected?.let { e ->
        FileActionSheet(
            entry = e,
            onDismiss = { selected = null },
            onPreview = {
                selected = null
                scope.launch {
                    val p = loadPreview(e)
                    if (p != null) preview = p
                    else Toast.makeText(context, context.getString(R.string.browse_no_preview), Toast.LENGTH_SHORT).show()
                }
            },
            onExport = {
                selected = null
                exportTarget = e
                saveLauncher.launch(e.name)
            },
            onOpenWith = {
                selected = null
                scope.launch { openWith(context, e) }
            },
        )
    }

    // 预览弹层
    preview?.let { p ->
        PreviewDialog(p) { preview = null }
    }
}

@Composable
private fun EntryRow(e: FatFileSystem.Entry, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            if (e.isDirectory) Icons.Filled.Folder else Icons.AutoMirrored.Filled.InsertDriveFile,
            contentDescription = null,
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(e.name, maxLines = 1, style = MaterialTheme.typography.bodyLarge)
            if (!e.isDirectory) {
                Text(
                    formatSize(e.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FileActionSheet(
    entry: FatFileSystem.Entry,
    onDismiss: () -> Unit,
    onPreview: () -> Unit,
    onExport: () -> Unit,
    onOpenWith: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(bottom = 24.dp)) {
            Text(
                entry.name,
                Modifier.padding(16.dp),
                style = MaterialTheme.typography.titleMedium,
                maxLines = 2,
            )
            HorizontalDivider()
            ActionItem(Icons.Filled.Visibility, stringResource(R.string.browse_action_preview), onPreview)
            ActionItem(Icons.Filled.Download, stringResource(R.string.browse_action_export), onExport)
            ActionItem(Icons.AutoMirrored.Filled.OpenInNew, stringResource(R.string.browse_action_open_with), onOpenWith)
        }
    }
}

@Composable
private fun ActionItem(icon: ImageVector, label: String, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null)
        Spacer(Modifier.width(16.dp))
        Text(label, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun PreviewDialog(preview: Preview, onDismiss: () -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surface,
        ) {
            Column(
                Modifier
                    .padding(16.dp)
                    .fillMaxWidth()
            ) {
                when (preview) {
                    is Preview.ImagePreview -> {
                        Text(preview.name, style = MaterialTheme.typography.titleSmall, maxLines = 1)
                        Spacer(Modifier.height(12.dp))
                        val bmp = remember(preview.bytes) {
                            BitmapFactory.decodeByteArray(preview.bytes, 0, preview.bytes.size)
                        }
                        if (bmp != null) {
                            Image(
                                bmp.asImageBitmap(),
                                contentDescription = preview.name,
                                modifier = Modifier.fillMaxWidth(),
                                contentScale = ContentScale.Fit,
                            )
                        } else {
                            Text(stringResource(R.string.browse_image_decode_failed))
                        }
                    }
                    is Preview.TextPreview -> {
                        Text(preview.name, style = MaterialTheme.typography.titleSmall, maxLines = 1)
                        Spacer(Modifier.height(12.dp))
                        Text(
                            preview.text,
                            Modifier
                                .fillMaxWidth()
                                .heightIn(max = 400.dp)
                                .verticalScroll(rememberScrollState()),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                        )
                    }
                }
            }
        }
    }
}

/** 读文件头部并判定可否预览。图片 ≤8MB 整读；文本 ≤256KB 读前段。 */
private suspend fun loadPreview(e: FatFileSystem.Entry): Preview? = withContext(Dispatchers.IO) {
    val name = e.name.lowercase()
    val imageExt = listOf(".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")
    val textExt = listOf(
        ".txt", ".log", ".md", ".json", ".xml", ".csv", ".ini", ".cfg",
        ".html", ".htm", ".kt", ".java", ".c", ".h", ".py", ".js",
    )

    when {
        imageExt.any { name.endsWith(it) } && e.size <= 8 * 1024 * 1024 -> {
            val bytes = MountManager.withFs { fs ->
                fs.readFile(e.firstCluster, e.size, 0, e.size.toInt())
            } ?: return@withContext null
            Preview.ImagePreview(e.name, bytes)
        }
        textExt.any { name.endsWith(it) } -> {
            val cap = minOf(e.size, 256 * 1024L).toInt()
            val bytes = MountManager.withFs { fs ->
                fs.readFile(e.firstCluster, e.size, 0, cap)
            } ?: return@withContext null
            Preview.TextPreview(e.name, String(bytes, Charsets.UTF_8))
        }
        else -> null
    }
}

/** 导出到缓存 + FileProvider，拉起「用其它应用打开」。 */
private suspend fun openWith(context: android.content.Context, e: FatFileSystem.Entry) {
    val file = withContext(Dispatchers.IO) {
        FileExport.exportToCache(context, e.name, e.firstCluster, e.size)
    }
    if (file == null) {
        Toast.makeText(context, context.getString(R.string.browse_export_open_failed), Toast.LENGTH_SHORT).show()
        return
    }
    val mime = guessMime(e.name)
    runCatching {
        context.startActivity(FileExport.openWithIntent(context, file, mime))
    }.onFailure {
        Toast.makeText(context, context.getString(R.string.browse_no_app_for_type), Toast.LENGTH_SHORT).show()
    }
}

private fun guessMime(name: String): String {
    val ext = name.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "txt", "log", "md", "ini", "cfg" -> "text/plain"
        "jpg", "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "gif" -> "image/gif"
        "pdf" -> "application/pdf"
        "mp4" -> "video/mp4"
        "mp3" -> "audio/mpeg"
        "zip" -> "application/zip"
        else -> "application/octet-stream"
    }
}

private fun formatSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
    bytes < 1024 * 1024 * 1024 -> "%.1f MB".format(bytes / 1024.0 / 1024.0)
    else -> "%.2f GB".format(bytes / 1024.0 / 1024.0)
}
