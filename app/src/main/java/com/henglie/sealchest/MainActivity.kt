package com.henglie.sealchest

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import com.henglie.sealchest.browse.BrowserScreen
import com.henglie.sealchest.browse.FileExport
import com.henglie.sealchest.crypto.NativeBridge
import com.henglie.sealchest.fs.FatFileSystem
import com.henglie.sealchest.fs.MountManager
import com.henglie.sealchest.ui.theme.SealchestTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SealchestTheme {
                // 顶层在「主屏」与「内置浏览器」之间切换。内置浏览器不依赖系统
                // DocumentsUI —— 老安卓（7/9）自带文件管理器多半不认第三方 SAF，
                // 内置浏览器保证任何机型都能浏览容器。
                var showBrowser by remember { mutableStateOf(false) }
                if (showBrowser && MountManager.isMounted) {
                    BrowserScreen(onExit = { showBrowser = false })
                } else {
                    HomeScreen(onBrowse = { showBrowser = true })
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // 进程还在但 Activity 销毁时不主动上锁：DocumentsProvider 可能仍在被别的 app
        // 读取挂载中的文件。真正上锁由用户显式触发或进程死亡（密钥随内存释放）。
    }
}

/** PRF 选项：显示名 string res id + 传给 native 的 ID（0=自动）。 */
private val PRF_OPTIONS = listOf(
    R.string.prf_auto to NativeBridge.PRF_AUTO,
    R.string.prf_sha512 to 1,
    R.string.prf_whirlpool to 2,
    R.string.prf_sha256 to 3,
    R.string.prf_blake2s to 4,
    R.string.prf_streebog to 5,
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun HomeScreen(onBrowse: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // 挂载态用 mountId 触发重组：unlock/lock 后自增。
    var mountToken by remember { mutableStateOf(0) }
    val mount = remember(mountToken) { MountManager.currentMount() }

    // 选中的待解锁容器。
    var pickedUri by remember { mutableStateOf<Uri?>(null) }
    var pickedName by remember { mutableStateOf("") }

    var password by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var prfIndex by remember { mutableStateOf(0) }

    var unlocking by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // 「关于」弹窗显隐。
    var showAbout by remember { mutableStateOf(false) }
    // 是否以可写方式挂载。选中容器若拿到写权限则默认开（读写），拿不到自动回落只读。
    var mountWritable by remember { mutableStateOf(true) }
    // 选中的 URI 是否实际拿到了可持久化写权限（源 provider 未必授予）。
    var uriWritable by remember { mutableStateOf(false) }
    // 选中的 keyfile URI 列表（可多选，顺序无关）。空 = 仅密码解锁。keyfile 只读内容、
    // 不持久化权限（解锁当次读完即弃），故存 URI 不存内容，解锁时才 SAF 读字节混入。
    var keyfileUris by remember { mutableStateOf<List<Uri>>(emptyList()) }

    val keyfilePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        // 追加去重（多次选择累加），不覆盖已选。keyfile 走当次读取，无需 take 持久权限。
        if (uris.isNotEmpty()) {
            keyfileUris = (keyfileUris + uris).distinct()
            error = null
        }
    }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            // 读权限必须拿到（DocumentsProvider 后续跨进程读容器密文），单独 take。
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            // 写权限额外单独尝试：源 provider 不授予写时这里失败，不连累读权限，
            // 只是 uriWritable 保持 false → 可写勾选不可用。
            uriWritable = runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }.isSuccess
            // 拿到写权限则默认读写打开，拿不到回落只读（换选容器时同步重置，不残留上次状态）。
            mountWritable = uriWritable
            // 换选容器时清空 keyfile：不同容器 keyfile 组不同，残留会导致误开卷失败。
            keyfileUris = emptyList()
            pickedUri = uri
            pickedName = queryDisplayName(context, uri) ?: uri.lastPathSegment
                ?: context.getString(R.string.mount_default_container)
            error = null
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.home_title)) },
                actions = {
                    IconButton(onClick = { showAbout = true }) {
                        Icon(
                            Icons.Filled.Info,
                            contentDescription = stringResource(R.string.about_title),
                        )
                    }
                },
            )
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.home_subtitle),
                style = MaterialTheme.typography.titleMedium,
            )

            if (!NativeBridge.isAvailable) {
                Text(
                    text = stringResource(R.string.native_unavailable),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyLarge,
                )
                return@Column
            }

            val m = mount
            if (m != null && !m.closed) {
                // ---- 已挂载态 ----
                MountedPanel(
                    fs = m.fs,
                    displayName = m.displayName,
                    scope = scope,
                    // 内置浏览器（主入口，不依赖系统文件管理器）。
                    onBrowse = onBrowse,
                    // 系统文件管理器（SAF，额外入口）。老安卓文件管理器可能不认。
                    onBrowseSaf = { launchBrowse(context) },
                    onLock = {
                        MountManager.lock(context)
                        FileExport.clearExportCache(context)
                        mountToken++
                        pickedUri = null
                        password = ""
                    },
                )
            } else {
                // ---- 未挂载态：选容器 + 解锁 ----
                OutlinedButton(
                    onClick = { picker.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (pickedUri == null) stringResource(R.string.home_pick_container)
                        else pickedName
                    )
                }

                if (pickedUri != null) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it; error = null },
                        label = { Text(stringResource(R.string.unlock_password)) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = pim,
                        onValueChange = { pim = it.filter(Char::isDigit); error = null },
                        label = { Text(stringResource(R.string.unlock_pim)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(
                        stringResource(R.string.unlock_prf),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    // PRF 选项用 FlowRow 自动换行：宽度不够就折行，避免定长两 Row
                    // 排版参差。每个 chip 设最小宽度，短标签也对齐成整齐编组。
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        PRF_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                            FilterChip(
                                selected = prfIndex == i,
                                onClick = { prfIndex = i },
                                label = { Text(stringResource(labelResId)) },
                                modifier = Modifier.widthIn(min = 96.dp),
                            )
                        }
                    }

                    if (error != null) {
                        Text(
                            error!!,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }

                    // 可写挂载开关。默认关（只读，第一版行为）。仅当源 URI 拿到写
                    // 权限（uriWritable）时可勾；勾上后解锁以 "rw" 打开，改动会加密写回真实容器。
                    FilterChip(
                        selected = mountWritable,
                        onClick = { if (uriWritable) mountWritable = !mountWritable },
                        enabled = uriWritable,
                        label = {
                            Text(
                                if (uriWritable) stringResource(R.string.mount_writable_on)
                                else stringResource(R.string.mount_writable_off)
                            )
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )

                    // Keyfile 入口。带 keyfile 的容器必须选齐同一组 keyfile 才能开卷（顺序无关）。
                    // 空 = 仅密码。选择走多选累加，可清空重来。keyfile 只读内容、不 take 持久权限。
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        OutlinedButton(
                            onClick = { keyfilePicker.launch(arrayOf("*/*")) },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                if (keyfileUris.isEmpty()) stringResource(R.string.unlock_keyfiles_none)
                                else stringResource(R.string.unlock_keyfiles_selected, keyfileUris.size)
                            )
                        }
                        if (keyfileUris.isNotEmpty()) {
                            TextButton(onClick = { keyfileUris = emptyList() }) {
                                Text(stringResource(R.string.unlock_keyfiles_clear))
                            }
                        }
                    }

                    Button(
                        onClick = {
                            val uri = pickedUri ?: return@Button
                            unlocking = true
                            error = null
                            val pw = password.toByteArray(Charsets.UTF_8)
                            val pimVal = pim.toIntOrNull() ?: 0
                            val prfVal = PRF_OPTIONS[prfIndex].second
                            val kfUris = keyfileUris
                            scope.launch {
                                val result = withContext(Dispatchers.IO) {
                                    runCatching {
                                        // keyfile 内容当次读入内存（各截断至 1 MiB 由 KeyfileMixer 处理）。
                                        val keyfiles = kfUris.mapNotNull { kfUri ->
                                            runCatching {
                                                context.contentResolver.openInputStream(kfUri)
                                                    ?.use { it.readBytes() }
                                            }.getOrNull()
                                        }
                                        MountManager.unlock(
                                            context, uri, pickedName, pw, pimVal, prfVal, mountWritable, keyfiles
                                        )
                                    }
                                }
                                pw.fill(0)
                                unlocking = false
                                result.onSuccess {
                                    password = ""
                                    mountToken++
                                }.onFailure {
                                    error = it.message
                                        ?: context.getString(R.string.unlock_wrong)
                                }
                            }
                        },
                        // 纯 keyfile 解锁：VC 允许空密码 + keyfile。有 keyfile 时放开空密码。
                        enabled = !unlocking && (password.isNotEmpty() || keyfileUris.isNotEmpty()),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        if (unlocking) {
                            CircularProgressIndicator(
                                modifier = Modifier.height(20.dp),
                                strokeWidth = 2.dp,
                            )
                            Spacer(Modifier.height(0.dp))
                            Text("  " + stringResource(R.string.unlock_unlocking))
                        } else {
                            Text(stringResource(R.string.unlock_submit))
                        }
                    }
                }
            }
        }

        // 「关于」弹窗：TopAppBar 信息按钮触发。
        if (showAbout) AboutDialog(onDismiss = { showAbout = false })
    }
}

/** 「关于」弹窗。展示描述、作者、可点项目地址、版本、核心致谢。 */
@Composable
private fun AboutDialog(onDismiss: () -> Unit) {
    val uriHandler = LocalUriHandler.current
    val projectUrl = "https://github.com/Henglie/Sealchest"
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.selftest_ok_button)) }
        },
        title = { Text(stringResource(R.string.about_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.about_app_desc),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(R.string.about_author_label) + "：" +
                        stringResource(R.string.about_author),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Row {
                    Text(
                        stringResource(R.string.about_project_label) + "：",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    // 可点超链接：蓝色下划线，点后用系统浏览器打开。
                    Text(
                        projectUrl,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            color = MaterialTheme.colorScheme.primary,
                            textDecoration = TextDecoration.Underline,
                        ),
                        modifier = Modifier.clickable { uriHandler.openUri(projectUrl) },
                    )
                }
                Text(
                    stringResource(R.string.about_version_label) + "：" +
                        BuildConfig.VERSION_NAME,
                    style = MaterialTheme.typography.bodyMedium,
                )
                // 供应链透明：编入的上游 VeraCrypt 版本、pinned commit、构建工具链、ABI。
                // 数据源为 build.gradle.kts 的 buildConfigField，与实际编译绑定，非手写。
                Text(
                    stringResource(R.string.about_upstream_label) + "：VeraCrypt " +
                        BuildConfig.VC_UPSTREAM_VERSION,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(R.string.about_upstream_commit_label) + "：" +
                        BuildConfig.VC_UPSTREAM_COMMIT,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.about_toolchain_label) + "：" +
                        BuildConfig.BUILD_TOOLCHAIN,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.about_abis_label) + "：" +
                        BuildConfig.BUILD_ABIS,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.about_supplychain_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.about_credit),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

@Composable
private fun MountedPanel(
    fs: FatFileSystem,
    displayName: String,
    scope: kotlinx.coroutines.CoroutineScope,
    onBrowse: () -> Unit,
    onBrowseSaf: () -> Unit,
    onLock: () -> Unit,
) {
    // 加解密自测态：null=未跑；running=跑中；否则为结果。
    var selfTesting by remember { mutableStateOf(false) }
    var selfTestResult by remember {
        mutableStateOf<com.henglie.sealchest.fs.VolumeReader.SelfTestResult?>(null)
    }
    var showSelfTest by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.LockOpen, contentDescription = null)
                Spacer(Modifier.height(0.dp))
                Text(
                    "  $displayName",
                    style = MaterialTheme.typography.titleLarge,
                )
            }
            val label = fs.volumeLabel.ifBlank { stringResource(R.string.mounted_no_label) }
            Text(
                stringResource(R.string.mounted_filesystem, fs.fatType.toString()),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(R.string.mounted_label, label),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }

    Spacer(Modifier.height(8.dp))

    Button(onClick = onBrowse, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.browse_title))
    }

    // 加解密自测：内存跑往返三判据，零写盘。为写入互通铺路的地基验证。
    OutlinedButton(
        onClick = {
            if (selfTesting) return@OutlinedButton
            selfTesting = true
            scope.launch {
                val r = withContext(Dispatchers.IO) {
                    runCatching { MountManager.selfTest() }.getOrNull()
                }
                selfTestResult = r
                selfTesting = false
                showSelfTest = true
            }
        },
        enabled = !selfTesting,
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (selfTesting) {
            CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
            Text(stringResource(R.string.selftest_running))
        } else {
            Text(stringResource(R.string.selftest_button))
        }
    }

    OutlinedButton(onClick = onLock, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.Lock, contentDescription = null)
        Text("  " + stringResource(R.string.browse_lock))
    }

    if (showSelfTest) {
        SelfTestDialog(
            result = selfTestResult,
            onDismiss = { showSelfTest = false },
        )
    }
}

/** 加解密自测结果弹窗。三判据逐条展示，全过才提示可安全写入。 */
@Composable
private fun SelfTestDialog(
    result: com.henglie.sealchest.fs.VolumeReader.SelfTestResult?,
    onDismiss: () -> Unit,
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            androidx.compose.material3.TextButton(onClick = onDismiss) { Text(stringResource(R.string.selftest_ok_button)) }
        },
        title = { Text(stringResource(R.string.selftest_title)) },
        text = {
            if (result == null) {
                Text(stringResource(R.string.selftest_unavailable))
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    fun mark(ok: Boolean) = if (ok) "✓" else "×"
                    Text(stringResource(R.string.selftest_roundtrip1, mark(result.encReproduces)))
                    Text(stringResource(R.string.selftest_encchanges, mark(result.encChanges)))
                    Text(stringResource(R.string.selftest_roundtrip2, mark(result.roundtripLossless)))
                    Spacer(Modifier.height(4.dp))
                    if (result.passed) {
                        Text(
                            stringResource(R.string.selftest_pass),
                            color = MaterialTheme.colorScheme.primary,
                        )
                    } else {
                        Text(
                            stringResource(R.string.selftest_fail),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
        },
    )
}

/** 用系统文件界面浏览已挂载卷的根。authority 与 Manifest 一致（含 debug 后缀）。 */
private fun launchBrowse(context: android.content.Context) {
    val authority = context.packageName + ".documents"
    val rootUri = DocumentsContract.buildRootUri(authority, "sealchest-root")
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(rootUri, DocumentsContract.Root.MIME_TYPE_ITEM)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    runCatching { context.startActivity(intent) }
}

/** 从 SAF URI 查显示名。 */
private fun queryDisplayName(context: android.content.Context, uri: Uri): String? {
    return context.contentResolver.query(
        uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null
    )?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }
}
