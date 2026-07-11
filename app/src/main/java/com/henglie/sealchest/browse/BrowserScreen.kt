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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.henglie.sealchest.fs.FsEntry
import com.henglie.sealchest.fs.MountManager
import com.henglie.sealchest.fs.VolumeFullException
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

/** 媒体查看器态：当前目录的媒体文件列表 + 初始定位（点哪个媒体就从哪个开始）。 */
private data class MediaViewerState(val files: List<FsEntry>, val index: Int)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrowserScreen(onExit: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val dirStack = remember { mutableStateListOf(DirFrame("", -1L, true)) }
    val current = dirStack.last()

    var entries by remember { mutableStateOf<List<FsEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var selected by remember { mutableStateOf<FsEntry?>(null) }
    var preview by remember { mutableStateOf<Preview?>(null) }
    // 全屏媒体查看器（图片画廊 / 视频 / 音频）。非空时覆盖浏览器。
    var mediaViewer by remember { mutableStateOf<MediaViewerState?>(null) }
    var exportTarget by remember { mutableStateOf<FsEntry?>(null) }
    // 写操作后自增，触发目录重载。
    var refreshToken by remember { mutableStateOf(0) }
    // 删除确认弹窗目标。
    var deleteConfirm by remember { mutableStateOf<FsEntry?>(null) }
    // 覆写：先选容器内文件，再选手机上的源文件。
    var overwriteTarget by remember { mutableStateOf<FsEntry?>(null) }
    // W16：目录动作单目标（点目录行的「更多」）。
    var dirMenuTarget by remember { mutableStateOf<FsEntry?>(null) }
    // W16：新建文件夹弹窗（true 时显示）。
    var showNewFolder by remember { mutableStateOf(false) }
    // W16：重命名弹窗目标。
    var renameTarget by remember { mutableStateOf<FsEntry?>(null) }
    // W16：删除文件夹确认目标。
    var rmdirConfirm by remember { mutableStateOf<FsEntry?>(null) }
    // W16：移动目标（选中的待移动项，非空时弹目录选择器）。
    var moveTarget by remember { mutableStateOf<FsEntry?>(null) }

    val writable = MountManager.isWritable

    // W16：统一的写操作结果提示 + 刷新。ok=true 走成功文案并刷新；异常走「不支持」提示。
    // okArgs 可选：成功提示含 %1$s 等占位符时传入格式化参数（如重命名的新名字）。
    fun runDirOp(okMsg: Int, failMsg: Int, okArgs: Array<Any?>? = null, op: (com.henglie.sealchest.fs.VolumeFs) -> Boolean) {
        scope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { MountManager.withWritableFs { fs -> op(fs) } ?: false }
            }
            when {
                outcome.isSuccess && outcome.getOrNull() == true -> {
                    refreshToken++
                    val msg = if (okArgs != null) context.getString(okMsg, *okArgs) else context.getString(okMsg)
                    Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                }
                outcome.exceptionOrNull() is UnsupportedOperationException ->
                    Toast.makeText(context, context.getString(R.string.browse_op_unsupported), Toast.LENGTH_SHORT).show()
                else -> Toast.makeText(context, context.getString(failMsg), Toast.LENGTH_SHORT).show()
            }
        }
    }

    // 当前目录的 firstCluster（<2 = 根目录，与 writeFile/deleteFile 的 dirFirstCluster 语义一致）。
    val dirCluster = if (current.isRoot) 0L else current.firstCluster

    // 载入当前目录内容。current 变 或 refreshToken 变即重载。
    LaunchedEffect(current.firstCluster, current.isRoot, refreshToken) {
        loading = true
        val list = withContext(Dispatchers.IO) {
            MountManager.withFs { fs ->
                if (current.isRoot) fs.listRoot() else fs.listDir(current.firstCluster)
            } ?: emptyList()
        }
        entries = list.sortedWith(
            compareByDescending<FsEntry> { it.isDirectory }
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

    // 导入文件到容器：从手机选文件 → 读入 → writeFile 写进当前目录。
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            scope.launch {
                val name = queryDisplayName(context, uri) ?: uri.lastPathSegment ?: "imported"
                val outcome = withContext(Dispatchers.IO) {
                    runCatching {
                        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                            ?: return@runCatching false
                        MountManager.withWritableFs { fs ->
                            fs.writeFile(dirCluster, name, bytes)
                        } ?: false
                    }
                }
                if (outcome.isSuccess && outcome.getOrNull() == true) {
                    refreshToken++
                    Toast.makeText(context, context.getString(R.string.browse_write_ok, name), Toast.LENGTH_SHORT).show()
                } else {
                    val msg = if (outcome.exceptionOrNull() is VolumeFullException) R.string.browse_write_full else R.string.browse_write_failed
                    Toast.makeText(context, context.getString(msg), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    // 覆写：选手机文件 → 读入 → overwriteFile。
    val overwriteLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        val target = overwriteTarget
        overwriteTarget = null
        if (uri != null && target != null) {
            scope.launch {
                val outcome = withContext(Dispatchers.IO) {
                    runCatching {
                        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                            ?: return@runCatching false
                        MountManager.withWritableFs { fs ->
                            fs.overwriteFile(dirCluster, target.name, bytes)
                        } ?: false
                    }
                }
                if (outcome.isSuccess && outcome.getOrNull() == true) {
                    refreshToken++
                    Toast.makeText(context, context.getString(R.string.browse_overwrite_ok, target.name), Toast.LENGTH_SHORT).show()
                } else {
                    val msg = if (outcome.exceptionOrNull() is VolumeFullException) R.string.browse_write_full else R.string.browse_overwrite_failed
                    Toast.makeText(context, context.getString(msg), Toast.LENGTH_SHORT).show()
                }
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
        floatingActionButton = {
            if (writable) {
                var fabMenu by remember { mutableStateOf(false) }
                Box {
                    FloatingActionButton(onClick = { fabMenu = true }) {
                        Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.browse_import_file))
                    }
                    DropdownMenu(expanded = fabMenu, onDismissRequest = { fabMenu = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.browse_import_file)) },
                            leadingIcon = { Icon(Icons.AutoMirrored.Filled.InsertDriveFile, contentDescription = null) },
                            onClick = { fabMenu = false; importLauncher.launch(arrayOf("*/*")) },
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.browse_new_folder)) },
                            leadingIcon = { Icon(Icons.Filled.CreateNewFolder, contentDescription = null) },
                            onClick = { fabMenu = false; showNewFolder = true },
                        )
                    }
                }
            }
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
                        EntryRow(
                            e = e,
                            onClick = {
                                if (e.isDirectory) {
                                    dirStack.add(DirFrame(e.name, e.firstCluster, false))
                                } else {
                                    selected = e
                                }
                            },
                            onMore = if (writable) {
                                { if (e.isDirectory) dirMenuTarget = e else selected = e }
                            } else null,
                        )
                    }
                }
            }
        }
    }

    // 文件动作单
    selected?.let { e ->
        FileActionSheet(
            entry = e,
            writable = writable,
            onDismiss = { selected = null },
            onPreview = {
                selected = null
                if (isMediaFile(e.name)) {
                    // 媒体文件走全屏查看器：收集当前目录所有媒体作画廊列表，从点击项开始。
                    val mediaFiles = entries.filter { !it.isDirectory && isMediaFile(it.name) }
                    mediaViewer = MediaViewerState(mediaFiles, mediaFiles.indexOf(e))
                } else {
                    scope.launch {
                        val p = loadPreview(e)
                        if (p != null) preview = p
                        else Toast.makeText(context, context.getString(R.string.browse_no_preview), Toast.LENGTH_SHORT).show()
                    }
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
            onOverwrite = {
                selected = null
                overwriteTarget = e
                overwriteLauncher.launch(arrayOf("*/*"))
            },
            onRename = {
                selected = null
                renameTarget = e
            },
            onMove = {
                selected = null
                moveTarget = e
            },
            onDelete = {
                selected = null
                deleteConfirm = e
            },
        )
    }

    // W16：目录动作单（重命名 / 移动 / 删除文件夹）
    dirMenuTarget?.let { e ->
        DirActionSheet(
            entry = e,
            onDismiss = { dirMenuTarget = null },
            onRename = { dirMenuTarget = null; renameTarget = e },
            onMove = { dirMenuTarget = null; moveTarget = e },
            onDelete = { dirMenuTarget = null; rmdirConfirm = e },
        )
    }

    // W16：新建文件夹弹窗
    if (showNewFolder) {
        NameInputDialog(
            title = stringResource(R.string.browse_new_folder),
            hint = stringResource(R.string.browse_new_folder_hint),
            initial = "",
            onDismiss = { showNewFolder = false },
            onConfirm = { name ->
                showNewFolder = false
                scope.launch {
                    val outcome = withContext(Dispatchers.IO) {
                        runCatching { MountManager.withWritableFs { fs -> fs.mkdir(dirCluster, name) } ?: 0L }
                    }
                    when {
                        outcome.isSuccess && (outcome.getOrNull() ?: 0L) >= 2L -> {
                            refreshToken++
                            Toast.makeText(context, context.getString(R.string.browse_new_folder_ok, name), Toast.LENGTH_SHORT).show()
                        }
                        outcome.exceptionOrNull() is UnsupportedOperationException ->
                            Toast.makeText(context, context.getString(R.string.browse_op_unsupported), Toast.LENGTH_SHORT).show()
                        else -> Toast.makeText(context, context.getString(R.string.browse_new_folder_failed), Toast.LENGTH_SHORT).show()
                    }
                }
            },
        )
    }

    // W16：重命名弹窗（文件 / 目录共用）
    renameTarget?.let { e ->
        NameInputDialog(
            title = stringResource(R.string.browse_rename_title),
            hint = stringResource(R.string.browse_rename_hint),
            initial = e.name,
            onDismiss = { renameTarget = null },
            onConfirm = { newName ->
                renameTarget = null
                if (newName != e.name) {
                    runDirOp(R.string.browse_rename_ok, R.string.browse_rename_failed, okArgs = arrayOf(newName)) { fs ->
                        fs.rename(dirCluster, e.name, newName)
                    }
                }
            },
        )
    }

    // W16：删除文件夹确认
    rmdirConfirm?.let { e ->
        AlertDialog(
            onDismissRequest = { rmdirConfirm = null },
            confirmButton = {
                TextButton(onClick = {
                    rmdirConfirm = null
                    runDirOp(R.string.browse_rmdir_ok, R.string.browse_rmdir_failed) { fs ->
                        fs.rmdir(dirCluster, e.name, false)
                    }
                }) { Text(stringResource(R.string.browse_delete_confirm_yes)) }
            },
            dismissButton = {
                TextButton(onClick = { rmdirConfirm = null }) { Text(stringResource(R.string.cancel)) }
            },
            title = { Text(stringResource(R.string.browse_rmdir_title)) },
            text = { Text(context.getString(R.string.browse_rmdir_msg, e.name)) },
        )
    }

    // W16：移动目标选择器（在容器内挑一个目录作落点）
    moveTarget?.let { e ->
        MoveDestinationDialog(
            entry = e,
            srcDirCluster = dirCluster,
            onDismiss = { moveTarget = null },
            onPick = { dstCluster ->
                moveTarget = null
                runDirOp(R.string.browse_move_ok, R.string.browse_move_failed) { fs ->
                    fs.move(dirCluster, e.name, dstCluster)
                }
            },
        )
    }

    // 删除确认弹窗
    deleteConfirm?.let { e ->
        AlertDialog(
            onDismissRequest = { deleteConfirm = null },
            confirmButton = {
                TextButton(onClick = {
                    deleteConfirm = null
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) {
                            MountManager.withWritableFs { fs ->
                                fs.deleteFile(dirCluster, e.name)
                            } ?: false
                        }
                        if (ok) {
                            refreshToken++
                            Toast.makeText(context, context.getString(R.string.browse_delete_ok, e.name), Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(context, context.getString(R.string.browse_delete_failed), Toast.LENGTH_SHORT).show()
                        }
                    }
                }) { Text(stringResource(R.string.browse_delete_confirm_yes)) }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirm = null }) { Text(stringResource(R.string.cancel)) }
            },
            title = { Text(stringResource(R.string.browse_delete_confirm_title)) },
            text = { Text(context.getString(R.string.browse_delete_confirm_msg, e.name)) },
        )
    }

    // 预览弹层
    preview?.let { p ->
        PreviewDialog(p) { preview = null }
    }

    // 全屏媒体查看器（图片画廊 / 视频 / 音频）
    mediaViewer?.let { state ->
        MediaViewer(
            files = state.files,
            initialIndex = state.index,
            onDismiss = { mediaViewer = null },
        )
    }
}

@Composable
private fun EntryRow(e: FsEntry, onClick: () -> Unit, onMore: (() -> Unit)? = null) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = if (onMore != null) 4.dp else 16.dp),
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
        if (onMore != null) {
            IconButton(onClick = onMore) {
                Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.browse_action_more))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FileActionSheet(
    entry: FsEntry,
    writable: Boolean,
    onDismiss: () -> Unit,
    onPreview: () -> Unit,
    onExport: () -> Unit,
    onOpenWith: () -> Unit,
    onOverwrite: () -> Unit,
    onRename: () -> Unit,
    onMove: () -> Unit,
    onDelete: () -> Unit,
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
            if (writable) {
                HorizontalDivider()
                ActionItem(Icons.Filled.Edit, stringResource(R.string.browse_action_overwrite), onOverwrite)
                ActionItem(Icons.Filled.Edit, stringResource(R.string.browse_action_rename), onRename)
                ActionItem(Icons.AutoMirrored.Filled.DriveFileMove, stringResource(R.string.browse_action_move), onMove)
                ActionItem(Icons.Filled.Delete, stringResource(R.string.browse_action_delete), onDelete)
            }
        }
    }
}

/** W16：目录动作单（重命名 / 移动 / 删除文件夹）。目录不可预览/导出/覆写。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DirActionSheet(
    entry: FsEntry,
    onDismiss: () -> Unit,
    onRename: () -> Unit,
    onMove: () -> Unit,
    onDelete: () -> Unit,
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
            ActionItem(Icons.Filled.Edit, stringResource(R.string.browse_action_rename), onRename)
            ActionItem(Icons.AutoMirrored.Filled.DriveFileMove, stringResource(R.string.browse_action_move), onMove)
            ActionItem(Icons.Filled.Delete, stringResource(R.string.browse_action_delete_folder), onDelete)
        }
    }
}

/** W16：单行文本输入弹窗（新建文件夹 / 重命名共用）。空名或未改名时确认按钮禁用。 */
@Composable
private fun NameInputDialog(
    title: String,
    hint: String,
    initial: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var text by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(
                onClick = { onConfirm(text.trim()) },
                enabled = text.trim().isNotEmpty(),
            ) { Text(stringResource(R.string.ok)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                singleLine = true,
                label = { Text(hint) },
            )
        },
    )
}

/**
 * W16：移动落点选择器。在容器内从根开始导航目录树，选一个目录作落点。
 * 禁止选中「源项自身所在目录」（原地移动无意义）与「被移动目录自身」（会成环）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MoveDestinationDialog(
    entry: FsEntry,
    srcDirCluster: Long,
    onDismiss: () -> Unit,
    onPick: (Long) -> Unit,
) {
    // 目录选择器自己的栈，独立于主浏览栈。栈顶 = 当前浏览目录。
    val navStack = remember { mutableStateListOf(DirFrame("", -1L, true)) }
    val cur = navStack.last()
    val curCluster = if (cur.isRoot) 0L else cur.firstCluster
    var dirs by remember { mutableStateOf<List<FsEntry>>(emptyList()) }

    LaunchedEffect(cur.firstCluster, cur.isRoot) {
        val list = withContext(Dispatchers.IO) {
            MountManager.withFs { fs ->
                if (cur.isRoot) fs.listRoot() else fs.listDir(cur.firstCluster)
            } ?: emptyList()
        }
        // 只列目录；排除被移动的目录自身（防选它进而成环）。
        dirs = list.filter { it.isDirectory && it.firstCluster != entry.firstCluster }
            .sortedBy { it.name.lowercase() }
    }

    // 落点不能是源目录本身（原地）。被移动项自身已在列表过滤掉，进不去也选不中。
    val canDropHere = curCluster != srcDirCluster

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = { onPick(curCluster) }, enabled = canDropHere) {
                Text(stringResource(R.string.browse_move_here))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
        title = { Text(stringResource(R.string.browse_move_title, entry.name)) },
        text = {
            Column(Modifier.fillMaxWidth().heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                if (navStack.size > 1) {
                    Row(
                        Modifier.fillMaxWidth()
                            .clickable { navStack.removeAt(navStack.lastIndex) }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                        Spacer(Modifier.width(12.dp))
                        Text(stringResource(R.string.browse_move_up))
                    }
                    HorizontalDivider()
                }
                if (dirs.isEmpty()) {
                    Text(stringResource(R.string.browse_empty), Modifier.padding(vertical = 12.dp))
                } else {
                    dirs.forEach { d ->
                        Row(
                            Modifier.fillMaxWidth()
                                .clickable { navStack.add(DirFrame(d.name, d.firstCluster, false)) }
                                .padding(vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(Icons.Filled.Folder, contentDescription = null)
                            Spacer(Modifier.width(12.dp))
                            Text(d.name, maxLines = 1)
                        }
                    }
                }
            }
        },
    )
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
private suspend fun loadPreview(e: FsEntry): Preview? = withContext(Dispatchers.IO) {
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
private suspend fun openWith(context: android.content.Context, e: FsEntry) {
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

private fun queryDisplayName(context: android.content.Context, uri: android.net.Uri): String? {
    return context.contentResolver.query(
        uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null
    )?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }
}
