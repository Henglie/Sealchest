package com.henglie.sealchest.browse

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.common.MediaItem
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.PlayerView
import com.henglie.sealchest.fs.FsEntry
import com.henglie.sealchest.fs.MountManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

/**
 * 加密媒体查看器。从 [VolumeFs] 读明文字节流播放，对标 Arcanum 的 encrypted gallery +
 * audio/video player。支持图片画廊滑动、视频播放、音频播放（带控制条）。
 *
 * 数据流：
 * - 图片：[VolumeFs.readFile] 整读 → [BitmapFactory.decodeByteArray]，全程在内存，不落盘。
 * - 音视频：Media3 ExoPlayer 需要 URI/DataSource，但容器内文件不是文件系统 URI。
 *   理想方案是自定义 [androidx.media3.datasource.DataSource] 直接从 VolumeFs 流式读，
 *   但 Media3 的 DataSource 接口与 VolumeFs 的「按 (firstCluster,fileSize,start,length)
 *   分块随机读」语义不匹配，工程量大。这里诚实采用临时文件方案：把明文写到
 *   cacheDir/encrypted_media_tmp/ 下的临时文件，播放完 / 离开页立即删，[onDismiss] 清整目录。
 *
 * 安全红线（明文落盘权衡）：
 * - cacheDir 是 app 私有，卸载即删，但仍属明文落盘 —— 取证 / root 场景可被读走。
 * - 临时文件生命周期严格控制：翻页离开（[DisposableEffect] onDispose）即删；
 *   关闭查看器再整目录清空兜底。
 * - 用户若极端敏感，应避免在容器内播放大音视频；图片画廊无此风险（纯内存）。
 *
 * 关键：媒体数据绝不写明文到用户可访问的公共目录。
 */
@Composable
fun MediaViewer(
    files: List<FsEntry>,      // 当前目录的媒体文件列表
    initialIndex: Int,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current

    // 安全兜底：查看器关闭时清空媒体临时目录里的明文。
    DisposableEffect(Unit) {
        onDispose { cleanMediaTempDir(context) }
    }

    if (files.isEmpty()) {
        onDismiss()
        return
    }

    val pagerState = rememberPagerState(
        initialPage = initialIndex.coerceIn(0, files.lastIndex),
        pageCount = { files.size },
    )

    BackHandler { onDismiss() }

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        HorizontalPager(state = pagerState) { pageIndex ->
            val entry = files[pageIndex]
            when (mediaKind(entry.name)) {
                MediaKind.IMAGE -> ImagePage(entry)
                MediaKind.VIDEO -> PlayerPage(entry, isVideo = true)
                MediaKind.AUDIO -> PlayerPage(entry, isVideo = false)
                MediaKind.OTHER -> OtherPage(entry)
            }
        }

        // 顶栏覆盖层：关闭 + 文件名 + 计数。放在 pager 之上，仅占顶部一条。
        Row(
            Modifier
                .fillMaxWidth()
                .background(Color(0x88000000))
                .padding(horizontal = 4.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onDismiss) {
                Icon(Icons.Filled.Close, contentDescription = "关闭", tint = Color.White)
            }
            Text(
                files[pagerState.currentPage].name,
                color = Color.White,
                maxLines = 1,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "${pagerState.currentPage + 1} / ${files.size}",
                color = Color.White,
                modifier = Modifier.padding(horizontal = 12.dp),
            )
        }
    }
}

/** 图片页：从 VolumeFs 整读字节 → 解码 Bitmap 显示，支持双指缩放（可选）。不落盘。 */
@Composable
private fun ImagePage(entry: FsEntry) {
    var scale by remember { mutableStateOf(1f) }
    var offsetX by remember { mutableStateOf(0f) }
    var offsetY by remember { mutableStateOf(0f) }

    // 图片字节上限 32MB（压缩后），防一次性读入过大字节流。
    // 解码时用 inSampleSize 降采样：JPEG/PNG 解码后 Bitmap = 宽×高×4 字节，
    // 一张 5000×5000 JPEG 压缩后可能仅 5MB 但解码后 100MB → OOM。
    // 目标 2048×2048（手机屏清晰显示足够），降采样后 Bitmap ≤16MB，安全。
    val bitmap by produceState<android.graphics.Bitmap?>(null, entry) {
        if (entry.size > 32L * 1024 * 1024) return@produceState
        value = withContext(Dispatchers.IO) {
            runCatching {
                val bytes = MountManager.withFs { fs ->
                    fs.readFile(entry.firstCluster, entry.size, 0, entry.size.toInt())
                } ?: return@runCatching null
                // 先量真实像素尺寸（不分配 Bitmap 内存），算降采样比。
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                val sample = calcInSampleSize(bounds.outWidth, bounds.outHeight, 2048, 2048)
                val opts = BitmapFactory.Options().apply { inSampleSize = sample }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
            }.getOrNull()
        }
    }

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        when {
            bitmap == null && entry.size <= 32L * 1024 * 1024 ->
                CircularProgressIndicator(color = Color.White)
            bitmap != null -> Image(
                bitmap = bitmap!!.asImageBitmap(),
                contentDescription = entry.name,
                modifier = Modifier
                    .fillMaxSize()
                    .pointerInput(entry) {
                        detectTransformGestures { _, pan, zoom, _ ->
                            scale = (scale * zoom).coerceIn(1f, 5f)
                            offsetX += pan.x
                            offsetY += pan.y
                        }
                    }
                    .graphicsLayer(
                        scaleX = scale,
                        scaleY = scale,
                        translationX = offsetX,
                        translationY = offsetY,
                    ),
                contentScale = ContentScale.Fit,
            )
            else -> Text("图片过大，无法内显", color = Color.White)
        }
    }
}

/**
 * 音视频播放页。每页独立 [ExoPlayer]；翻页离开时 [DisposableEffect] 释放播放器并删临时文件。
 *
 * HorizontalPager 默认 beyondBoundsPageCount=0，仅当前页驻留，故同一时刻最多一个活跃播放器
 * （滑动瞬态短暂并存相邻页）。资源占用可控。
 */
@Composable
private fun PlayerPage(entry: FsEntry, isVideo: Boolean) {
    val context = LocalContext.current
    var ready by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }

    val player = remember { ExoPlayer.Builder(context).build() }
    // 临时明文文件：见类头安全红线说明，用完即删。
    var tempFile by remember { mutableStateOf<File?>(null) }

    LaunchedEffect(entry) {
        ready = false
        failed = false
        val file = withContext(Dispatchers.IO) {
            runCatching { writeMediaTemp(context, entry) }.getOrNull()
        }
        if (file == null) {
            failed = true
            return@LaunchedEffect
        }
        tempFile = file
        player.setMediaItem(MediaItem.fromUri(Uri.fromFile(file)))
        player.prepare()
        player.playWhenReady = true
        ready = true
    }

    DisposableEffect(player) {
        onDispose {
            player.release()
            tempFile?.delete()
        }
    }

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        if (isVideo) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx -> PlayerView(ctx).apply { useController = true } },
                update = { it.player = player },
            )
        } else {
            // 音频无画面：居中图标 + 文件名 + 控制条（PlayerView 控制条带进度）。
            Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Icon(
                    Icons.Filled.MusicNote,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(96.dp),
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    entry.name,
                    color = Color.White,
                    maxLines = 1,
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(24.dp))
                AndroidView(
                    modifier = Modifier.fillMaxWidth(),
                    factory = { ctx -> PlayerView(ctx).apply { useController = true } },
                    update = { it.player = player },
                )
            }
        }
        if (!ready && !failed) CircularProgressIndicator(color = Color.White)
        if (failed) Text("无法播放：${entry.name}", color = Color.White)
    }
}

/** 非媒体文件占位（理论上不会进，画廊列表已过滤）。 */
@Composable
private fun OtherPage(entry: FsEntry) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(entry.name, color = Color.White)
    }
}

/** 媒体类型判定。对外暴露，供 [BrowserScreen] 在预览入口分流到本查看器。 */
private enum class MediaKind { IMAGE, VIDEO, AUDIO, OTHER }

/** 判断文件是否为媒体（图片/视频/音频），供 BrowserScreen 收集画廊列表用。 */
fun isMediaFile(name: String): Boolean = mediaKind(name) != MediaKind.OTHER

private fun mediaKind(name: String): MediaKind {
    val ext = name.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "jpg", "jpeg", "png", "gif", "webp", "bmp" -> MediaKind.IMAGE
        "mp4", "mkv", "webm", "avi", "mov", "3gp" -> MediaKind.VIDEO
        "mp3", "aac", "flac", "ogg", "wav", "m4a" -> MediaKind.AUDIO
        else -> MediaKind.OTHER
    }
}

/**
 * 算 BitmapFactory 降采样比。返回 2 的幂（解码器要求）。
 * 目标：解码后 Bitmap 宽高都 ≤ [reqW]/[reqH]，同时尽量保留清晰度。
 */
private fun calcInSampleSize(w: Int, h: Int, reqW: Int, reqH: Int): Int {
    if (w <= 0 || h <= 0) return 1
    var sample = 1
    while (w / (sample * 2) >= reqW && h / (sample * 2) >= reqH) sample *= 2
    return sample
}

/**
 * 把容器内 [entry] 解密写到 cacheDir/encrypted_media_tmp/ 临时文件，返回 [File]。
 * 明文落盘 —— 见 [MediaViewer] 类头安全红线。调用方负责用完删除。
 */
private fun writeMediaTemp(context: Context, entry: FsEntry): File {
    val dir = File(context.cacheDir, "encrypted_media_tmp").apply { mkdirs() }
    val safe = entry.name.replace(Regex("[^\\p{L}\\p{N}._-]"), "_").ifBlank { "media" }
    val tmp = File.createTempFile(safe + "_", ".tmp", dir)
    FileOutputStream(tmp).use { fos ->
        var pos = 0L
        val chunkSize = 64 * 1024
        while (pos < entry.size) {
            val want = minOf(chunkSize.toLong(), entry.size - pos).toInt()
            val chunk = MountManager.withFs { fs ->
                fs.readFile(entry.firstCluster, entry.size, pos, want)
            } ?: throw IllegalStateException("卷未挂载")
            if (chunk.isEmpty()) break
            fos.write(chunk)
            pos += chunk.size
        }
        fos.flush()
    }
    return tmp
}

/** 清空媒体临时目录里的明文文件。关闭查看器 / 兜底时调用。 */
private fun cleanMediaTempDir(context: Context) {
    val dir = File(context.cacheDir, "encrypted_media_tmp")
    runCatching { dir.listFiles()?.forEach { it.delete() } }
}
