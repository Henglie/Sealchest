package com.henglie.sealchest

import android.content.Intent
import android.net.Uri
import java.io.File
import android.os.Bundle
import android.provider.DocumentsContract
import androidx.fragment.app.FragmentActivity
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.henglie.sealchest.browse.BrowserScreen
import com.henglie.sealchest.browse.FileExport
import com.henglie.sealchest.crypto.NativeBridge
import com.henglie.sealchest.fs.VolumeFs
import com.henglie.sealchest.core.AutoLock
import com.henglie.sealchest.core.PinManager
import com.henglie.sealchest.core.Settings
import com.henglie.sealchest.fs.MountManager
import com.henglie.sealchest.ui.PinGateScreen
import com.henglie.sealchest.ui.theme.SealchestTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {
    // 任何触摸/滑动都重置自动锁定计时（见 AutoLock）。挂载时才真正计时。
    override fun onUserInteraction() {
        super.onUserInteraction()
        AutoLock.touch()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SealchestTheme {
                // 顶层在「主屏」与「内置浏览器」之间切换。内置浏览器不依赖系统
                // DocumentsUI —— 老安卓（7/9）自带文件管理器多半不认第三方 SAF，
                // 内置浏览器保证任何机型都能浏览容器。
                var showBrowser by remember { mutableStateOf(false) }
                var showCreate by remember { mutableStateOf(false) }

                val ctx = LocalContext.current
                // PIN 门禁：已设 PIN 则启动时先拦在 PinGateScreen，验证通过才进主界面。
                var pinUnlocked by remember { mutableStateOf(!PinManager.isPinSet(ctx)) }
                val createScope = rememberCoroutineScope()
                // 建卷参数暂存：CreateVolumeScreen 采集后先存这里，再启 CreateDocument 建空文件，
                // 拿到 URI 才真正 VolumeCreator.create。密码字节随 params，成功/失败后抹除。
                var pendingParams by remember {
                    mutableStateOf<com.henglie.sealchest.create.CreateParams?>(null)
                }
                var creating by remember { mutableStateOf(false) }
                var createMsg by remember { mutableStateOf<String?>(null) }

                // 建卷文件：SAF 建新文档（.hc），拿到可写 URI 后预分配 + 写卷头 + 空 FAT。
                val createFileLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.CreateDocument("application/octet-stream")
                ) { uri ->
                    val params = pendingParams
                    if (uri == null || params == null) {
                        // 用户取消建文件：抹密码，回到向导。
                        params?.password?.fill(0)
                        pendingParams = null
                        return@rememberLauncherForActivityResult
                    }
                    creating = true
                    createMsg = null
                    val totalSize = params.sizeBytes + 2L * 131072   // 数据区 + 主/备头组各 128KB
                    createScope.launch {
                        val result = withContext(Dispatchers.IO) {
                            runCatching {
                                // 预分配到目标总大小：VolumeCreator 要在末尾写备份头。
                                ctx.contentResolver.openFileDescriptor(uri, "rw")?.use { pfd ->
                                    java.io.RandomAccessFile("/proc/self/fd/${pfd.fd}", "rw").use { raf ->
                                        raf.setLength(totalSize)
                                    }
                                } ?: throw java.io.FileNotFoundException("无法打开新建容器文件")
                                com.henglie.sealchest.fs.VolumeCreator.create(
                                    resolver = ctx.contentResolver,
                                    containerUri = uri,
                                    ea = params.algorithm,
                                    prf = params.prf,
                                    pim = params.pim,
                                    password = params.password,
                                    keyfiles = emptyList(),
                                    volumeSizeBytes = params.sizeBytes,
                                    fsType = params.fsType,
                                    clusterSize = params.clusterSize,
                                    dynamic = params.dynamic,
                                    randomFill = params.randomFill,
                                ).getOrThrow()
                            }
                        }
                        params.password.fill(0)
                        pendingParams = null
                        creating = false
                        createMsg = result.fold(
                            { ctx.getString(R.string.create_ok) },
                            { it.message ?: ctx.getString(R.string.create_failed) },
                        )
                        if (result.isSuccess) showCreate = false
                    }
                }

                if (!pinUnlocked) {
                    PinGateScreen(
                        biometricEnabled = com.henglie.sealchest.core.Settings.biometricUnlockEnabled(ctx),
                        onPinCorrect = { pinUnlocked = true },
                        onClearPin = {
                            PinManager.clearPin(ctx)
                            pinUnlocked = true
                        },
                    )
                } else if (showCreate) {
                    com.henglie.sealchest.create.CreateVolumeScreen(
                        busy = creating,
                        message = createMsg,
                        onCancel = { if (!creating) { showCreate = false; createMsg = null } },
                        onCreate = { params ->
                            // 采集完参数：暂存 + 启动建文件（默认文件名带 .hc 后缀，与 VeraCrypt 惯例一致）。
                            pendingParams = params
                            createMsg = null
                            createFileLauncher.launch("sealchest-container.hc")
                        },
                    )
                } else if (showBrowser && MountManager.isMounted) {
                    BrowserScreen(onExit = { showBrowser = false })
                } else {
                    HomeScreen(
                        onBrowse = { showBrowser = true },
                        onCreateVolume = { showCreate = true; createMsg = null },
                    )
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

/** 创建（含隐藏卷）用的加密算法选项：显示名 res + native EA ID。与 CreateVolumeScreen 对齐。 */
private val CREATE_ALGO_OPTIONS = listOf(
    R.string.create_algo_aes to 1,
    R.string.create_algo_serpent to 2,
    R.string.create_algo_twofish to 3,
    R.string.create_algo_camellia to 4,
    R.string.create_algo_kuznyechik to 5,
)

/** 创建用 PRF 选项：不含「自动」（创建必须指定确定 PRF）。显示名 res + native PRF ID。 */
private val CREATE_PRF_OPTIONS = listOf(
    R.string.prf_sha512 to 1,
    R.string.prf_whirlpool to 2,
    R.string.prf_sha256 to 3,
    R.string.prf_blake2s to 4,
    R.string.prf_streebog to 5,
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun HomeScreen(onBrowse: () -> Unit, onCreateVolume: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // 挂载态用 mountId 触发重组：unlock/lock 后自增。
    var mountToken by remember { mutableStateOf(0) }
    val mount = remember(mountToken) { MountManager.currentMount() }

    // 选中的待解锁容器。
    var pickedUri by remember { mutableStateOf<Uri?>(null) }
    var pickedName by remember { mutableStateOf("") }
    var favTick by remember { mutableStateOf(0) }

    var password by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var prfIndex by remember { mutableStateOf(Settings.defaultPrfIndex(context)) }

    var unlocking by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // 「关于」弹窗显隐。
    var showAbout by remember { mutableStateOf(false) }
    var showSettings by remember { mutableStateOf(false) }
    // 收藏项重命名（X9）：待重命名的 uri + 输入文本。null 表示对话框关闭。
    var renameFavoriteUri by remember { mutableStateOf<String?>(null) }
    var renameFavoriteText by remember { mutableStateOf("") }
    // 是否以可写方式挂载。选中容器若拿到写权限则默认开（读写），拿不到自动回落只读。
    var mountWritable by remember { mutableStateOf(Settings.defaultMountWritable(context)) }
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

    // 卷头工具（A2 救砖）状态：弹窗显隐 + 忙碌标志 + 结果提示。
    var showHeaderTool by remember { mutableStateOf(false) }
    var headerBusy by remember { mutableStateOf(false) }
    var headerMsg by remember { mutableStateOf<String?>(null) }
    var showRescueManager by remember { mutableStateOf(false) }

    // 救援文件管理：列出/清理 app 私有目录自动兜底的旧头组备份（旧密码可解，须可清）。
    var showRescueMgr by remember { mutableStateOf(false) }

    // 改密码（B1）状态：弹窗显隐 + 忙碌 + 结果提示 + 新凭据（旧凭据复用解锁区已填的）。
    var showChangePwd by remember { mutableStateOf(false) }
    var changePwdBusy by remember { mutableStateOf(false) }
    var changePwdMsg by remember { mutableStateOf<String?>(null) }
    var newPassword by remember { mutableStateOf("") }
    var newPim by remember { mutableStateOf("") }
    var newPrfIndex by remember { mutableStateOf(0) }
    var newKeyfileUris by remember { mutableStateOf<List<Uri>>(emptyList()) }

    // 隐藏卷创建（C2）状态：外层凭据复用解锁区已填的，隐藏卷凭据在对话框收集。
    var showCreateHidden by remember { mutableStateOf(false) }
    var createHiddenBusy by remember { mutableStateOf(false) }
    var createHiddenMsg by remember { mutableStateOf<String?>(null) }
    var hiddenPassword by remember { mutableStateOf("") }
    var hiddenSizeMb by remember { mutableStateOf("") }
    var hiddenAlgoIndex by remember { mutableStateOf(0) }
    var hiddenPrfIndex by remember { mutableStateOf(0) }
    var hiddenPimText by remember { mutableStateOf("") }

    // 隐藏卷 keyfile（C2 增强，对齐桌面 VC：隐藏卷可带 keyfile）
    var hiddenKeyfileUris by remember { mutableStateOf<List<Uri>>(emptyList()) }

    // 卷扩展（X17）状态：原凭据复用解锁区已填的，这里只收新大小。
    var showExpandVolume by remember { mutableStateOf(false) }
    var expandBusy by remember { mutableStateOf(false) }
    var expandMsg by remember { mutableStateOf<String?>(null) }
    var expandSizeMb by remember { mutableStateOf("") }
    var expandCurrentSize by remember { mutableStateOf<Long?>(null) }

    // 分区加密探针（X2/X3，root-gated）：只读枚举块设备，不加密。
    var showBlockDevice by remember { mutableStateOf(false) }
    var blockDeviceBusy by remember { mutableStateOf(false) }
    var blockDeviceList by remember { mutableStateOf<List<com.henglie.sealchest.core.BlockDeviceEnumerator.BlockDevice>>(emptyList()) }
    var blockDeviceMsg by remember { mutableStateOf<String?>(null) }
    var blockDeviceRootGranted by remember { mutableStateOf(false) }

    // F2：块设备解锁流程状态。选设备→弹密码框→调 BlockDeviceUnlocker。
    var blockDeviceUnlockTarget by remember { mutableStateOf<com.henglie.sealchest.core.BlockDeviceEnumerator.BlockDevice?>(null) }
    var blockDeviceUnlockPwd by remember { mutableStateOf("") }
    var blockDeviceUnlockWritable by remember { mutableStateOf(false) }

    // F3：系统暴露流程状态。已挂载+root 时可把明文同步到目录。
    var showExpose by remember { mutableStateOf(false) }
    var exposeDir by remember { mutableStateOf("/data/local/tmp/sealchest") }
    var exposeBusy by remember { mutableStateOf(false) }
    var exposeMsg by remember { mutableStateOf<String?>(null) }

    val newKeyfilePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (uris.isNotEmpty()) {
            newKeyfileUris = (newKeyfileUris + uris).distinct()
            changePwdMsg = null
        }
    }

    // F4：POST_NOTIFICATIONS 运行时权限（Android 13+）。解锁成功时请求，保活前台服务通知才显示。
    val notifPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* 结果不关心：拒绝也能跑，只是没通知 */ }

    // 导出卷头备份：选保存位置 → 原始 128KB 主头组转储（只读容器，最安全）。

    // 隐藏卷 keyfile 选择器（C2 增强）：多选，追加去重。隐藏卷凭据独立于外层。
    val hiddenKeyfilePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (uris.isNotEmpty()) {
            hiddenKeyfileUris = (hiddenKeyfileUris + uris).distinct()
            createHiddenMsg = null
        }
    }

    val exportHeaderLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { dest ->
        val uri = pickedUri
        if (dest != null && uri != null) {
            headerBusy = true
            scope.launch {
                val r = withContext(Dispatchers.IO) {
                    com.henglie.sealchest.fs.VolumeHeaderTool.export(context.contentResolver, uri, dest)
                }
                headerBusy = false
                headerMsg = r.fold(
                    { context.getString(R.string.header_export_ok) },
                    { it.message ?: context.getString(R.string.header_export_failed) },
                )
            }
        }
    }

    // 救砖：先让用户选“救援文件”保存位置（覆盖前的可逆兜底），onResult 才真正跑恢复。
    // 恢复内部严格序：验证备份头能开卷 → 导出当前主头到救援文件 → 备份头组覆盖主头组。
    val rescueLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { rescueDest ->
        val uri = pickedUri
        if (rescueDest != null && uri != null) {
            headerBusy = true
            val pw = password.toByteArray(Charsets.UTF_8)
            val pimVal = pim.toIntOrNull() ?: 0
            val prfVal = PRF_OPTIONS[prfIndex].second
            val kfUris = keyfileUris
            scope.launch {
                val r = withContext(Dispatchers.IO) {
                    runCatching {
                        val keyfiles = kfUris.mapNotNull { kfUri ->
                            context.contentResolver.openInputStream(kfUri)?.use { it.readBytes() }
                        }
                        com.henglie.sealchest.fs.VolumeHeaderTool.restoreFromEmbedded(
                            context.contentResolver, uri, pw, pimVal, prfVal, keyfiles, rescueDest,
                            autoRescueFile(context, uri),
                        ).getOrThrow()
                    }
                }
                pw.fill(0)
                headerBusy = false
                headerMsg = r.fold(
                    { context.getString(R.string.header_restore_ok) },
                    { it.message ?: context.getString(R.string.header_restore_failed) },
                )
                if (r.isSuccess) showHeaderTool = false
            }
        }
    }

    // 改密码（B1）：先选“救援文件”保存位置（写头前的可逆兜底），onResult 才真正执行。
    // 旧凭据取解锁区已填的（password/pim/prfIndex/keyfileUris），新凭据取对话框内的。
    val changePwdLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { rescueDest ->
        val uri = pickedUri
        if (rescueDest != null && uri != null) {
            changePwdBusy = true
            val oldPw = password.toByteArray(Charsets.UTF_8)
            val oldPimVal = pim.toIntOrNull() ?: 0
            val oldPrfVal = PRF_OPTIONS[prfIndex].second
            val oldKfUris = keyfileUris
            val newPw = newPassword.toByteArray(Charsets.UTF_8)
            val newPimVal = newPim.toIntOrNull() ?: 0
            val newPrfVal = PRF_OPTIONS[newPrfIndex].second
            val newKfUris = newKeyfileUris
            scope.launch {
                val r = withContext(Dispatchers.IO) {
                    runCatching {
                        val oldKeyfiles = oldKfUris.mapNotNull { kfUri ->
                            runCatching {
                                context.contentResolver.openInputStream(kfUri)?.use { it.readBytes() }
                            }.getOrNull()
                        }
                        val newKeyfiles = newKfUris.mapNotNull { kfUri ->
                            runCatching {
                                context.contentResolver.openInputStream(kfUri)?.use { it.readBytes() }
                            }.getOrNull()
                        }
                        com.henglie.sealchest.fs.PasswordChanger.change(
                            context.contentResolver, uri,
                            oldPw, oldPimVal, oldPrfVal, oldKeyfiles,
                            newPw, newPimVal, newPrfVal, newKeyfiles,
                            rescueDest,
                            autoRescueFile(context, uri),
                        ).getOrThrow()
                    }
                }
                oldPw.fill(0)
                newPw.fill(0)
                changePwdBusy = false
                changePwdMsg = r.fold(
                    { context.getString(R.string.change_pwd_ok) },
                    { it.message ?: context.getString(R.string.change_pwd_failed) },
                )
                if (r.isSuccess) {
                    // 改成功：清空新旧口令输入，防残留。
                    newPassword = ""; newPim = ""; newKeyfileUris = emptyList()
                    showChangePwd = false
                }
            }
        }
    }

    // 创建隐藏卷（C2）：外层凭据取上方解锁区已填值，隐藏卷凭据取对话框。容器已存在、
    // 无需 CreateDocument，直接在 IO 线程跑 HiddenVolumeCreator（读外层 FAT 算安全区 →
    // 生成隐藏卷头 → 写隐藏主/备头 → 格式化隐藏 FAT）。
    // 卷扩展（X17）：选救援文件后执行 VolumeExpander。主密钥不动，换头+扩文件。
    // 新总大小 = 用户输入 MB → 数据区大小 = 总大小 - 2*128KB（主/备头组）。
    val expandLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { rescueDest ->
        val uri = pickedUri
        if (rescueDest != null && uri != null) {
            expandBusy = true
            val pw = password.toByteArray(Charsets.UTF_8)
            val pimVal = pim.toIntOrNull() ?: 0
            val prfVal = PRF_OPTIONS[prfIndex].second
            val kfUris = keyfileUris
            val newTotalBytes = (expandSizeMb.toLongOrNull() ?: 0L) * 1024L * 1024L
            val newDataAreaSize = newTotalBytes - 2L * 131072L
            scope.launch {
                val r = withContext(Dispatchers.IO) {
                    runCatching {
                        require(newDataAreaSize > 0) { context.getString(R.string.expand_volume_too_small) }
                        val keyfiles = kfUris.mapNotNull { kfUri ->
                            runCatching {
                                context.contentResolver.openInputStream(kfUri)?.use { it.readBytes() }
                            }.getOrNull()
                        }
                        com.henglie.sealchest.fs.VolumeExpander.expand(
                            context.contentResolver, uri,
                            pw, pimVal, prfVal, keyfiles,
                            newDataAreaSize, rescueDest,
                            autoRescueFile(context, uri),
                        ).getOrThrow()
                    }
                }
                pw.fill(0)
                expandBusy = false
                val newTotal = r.getOrNull()?.let { it.second + 2L * 131072L }
                expandMsg = r.fold(
                    { context.getString(R.string.expand_volume_ok, "%.1f MB".format(newTotal!! / 1024.0 / 1024.0)) },
                    { it.message ?: context.getString(R.string.expand_volume_failed) },
                )
                if (r.isSuccess) {
                    expandSizeMb = ""; expandCurrentSize = null
                    showExpandVolume = false
                }
            }
        }
    }
    val runCreateHidden: () -> Unit = run@{
        val uri = pickedUri ?: return@run
        createHiddenBusy = true
        createHiddenMsg = null
        val outerPw = password.toByteArray(Charsets.UTF_8)
        val outerPimVal = pim.toIntOrNull() ?: 0
        val outerPrfVal = PRF_OPTIONS[prfIndex].second
        val outerKfUris = keyfileUris
        val hiddenPw = hiddenPassword.toByteArray(Charsets.UTF_8)
        val hiddenPimVal = hiddenPimText.toIntOrNull() ?: 0
        val eaVal = CREATE_ALGO_OPTIONS[hiddenAlgoIndex].second
        val prfVal = CREATE_PRF_OPTIONS[hiddenPrfIndex].second
        val hiddenBytes = (hiddenSizeMb.toLongOrNull() ?: 0L) * 1024L * 1024L
        scope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching {
                    val outerKeyfiles = outerKfUris.mapNotNull { kfUri ->
                        runCatching {
                            context.contentResolver.openInputStream(kfUri)?.use { it.readBytes() }
                        }.getOrNull()
                    }
                    val hiddenKfUris = hiddenKeyfileUris
                    val hiddenKeyfiles = hiddenKfUris.mapNotNull { kfUri ->
                        runCatching {
                            context.contentResolver.openInputStream(kfUri)?.use { it.readBytes() }
                        }.getOrNull()
                    }
                    com.henglie.sealchest.fs.HiddenVolumeCreator.create(
                        resolver = context.contentResolver,
                        containerUri = uri,
                        outerPassword = outerPw,
                        outerPim = outerPimVal,
                        outerPrf = outerPrfVal,
                        outerKeyfiles = outerKeyfiles,
                        hiddenPassword = hiddenPw,
                        hiddenPim = hiddenPimVal,
                        hiddenKeyfiles = hiddenKeyfiles,
                        hiddenEa = eaVal,
                        hiddenPrf = prfVal,
                        hiddenVolumeBytes = hiddenBytes,
                    ).getOrThrow()
                }
            }
            outerPw.fill(0); hiddenPw.fill(0)
            createHiddenBusy = false
            createHiddenMsg = r.fold(
                { context.getString(R.string.create_hidden_ok) },
                { it.message ?: context.getString(R.string.create_hidden_failed) },
            )
            if (r.isSuccess) {
                hiddenPassword = ""; hiddenSizeMb = ""; hiddenPimText = ""
                showCreateHidden = false
            }
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
            // 拿到写权限且默认读写则可写打开，否则只读（X13：默认挂载模式偏好 + 实际权限双门控）。
            mountWritable = uriWritable && Settings.defaultMountWritable(context)
            // 换选容器时清空 keyfile：不同容器 keyfile 组不同，残留会导致误开卷失败。
            keyfileUris = emptyList()
            pickedUri = uri
            pickedName = queryDisplayName(context, uri) ?: uri.lastPathSegment
                ?: context.getString(R.string.mount_default_container)
            error = null
        }
    }

    // 「关于」整屏：showAbout 为真时渲染独立界面并 early-return，替代原弹窗。
    if (showAbout) {
        AboutScreen(onBack = { showAbout = false })
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.home_title)) },
                actions = {
                    IconButton(onClick = { showSettings = true }) {
                        Icon(Icons.Filled.Settings, contentDescription = stringResource(R.string.settings_title))
                    }
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
        val mnt = mount
        if (NativeBridge.isAvailable && (mnt == null || mnt.closed) && pickedUri == null) {
            // ================= 落地页：品牌大标题居中偏上，主按钮居中偏下 =================
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(inner)
                    .padding(horizontal = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Spacer(Modifier.weight(1f))
                Text(
                    text = stringResource(R.string.home_title),
                    style = MaterialTheme.typography.displaySmall,
                    color = MaterialTheme.colorScheme.primary,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    text = stringResource(R.string.home_subtitle),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.weight(1.2f))
                Button(
                    onClick = { picker.launch(arrayOf("*/*")) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 52.dp),
                ) {
                    Text(stringResource(R.string.home_pick_container))
                }
                Spacer(Modifier.height(12.dp))
                OutlinedButton(
                    onClick = onCreateVolume,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 52.dp),
                ) {
                    Text(stringResource(R.string.create_entry))
                }
                val favs = remember(favTick) { Settings.favorites(context) }
                if (favs.isNotEmpty()) {
                    Spacer(Modifier.height(24.dp))
                    Text(
                        text = stringResource(R.string.favorites_title),
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    favs.forEach { fav ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = fav.name,
                                    modifier = Modifier
                                        .weight(1f)
                                        .clickable {
                                            val u = Uri.parse(fav.uri)
                                            uriWritable = runCatching {
                                                context.contentResolver.takePersistableUriPermission(
                                                    u, Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                                                )
                                            }.isSuccess
                                            runCatching {
                                                context.contentResolver.takePersistableUriPermission(
                                                    u, Intent.FLAG_GRANT_READ_URI_PERMISSION
                                                )
                                            }
            mountWritable = uriWritable && Settings.defaultMountWritable(context)
                                            keyfileUris = emptyList()
                                            pickedUri = u
                                            pickedName = fav.name
                                            error = null
                                        },
                                )
                                TextButton(onClick = {
                                    renameFavoriteUri = fav.uri
                                    renameFavoriteText = fav.name
                                }) {
                                    Text(stringResource(R.string.favorites_rename))
                                }
                                TextButton(onClick = {
                                    Settings.reorderFavorite(context, fav.uri, 0)
                                    favTick++
                                }) {
                                    Text(stringResource(R.string.favorites_pin))
                                }
                                TextButton(onClick = {
                                    Settings.removeFavorite(context, fav.uri)
                                    favTick++
                                }) {
                                    Text(stringResource(R.string.favorites_remove))
                                }
                            }
                        }
                    }
                }
                Spacer(Modifier.weight(0.9f))
            }
        } else {
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
                    mount = m,
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

                // 创建新容器入口：仅未选容器时显示，与「选已有容器」并列。
                if (pickedUri == null) {
                    OutlinedButton(
                        onClick = onCreateVolume,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.create_entry))
                    }

                    // 收藏容器列表：点名字快速选中并尝试拿读写权限，右侧移除（只删收藏，不动容器）。
                    val favs = remember(favTick) { Settings.favorites(context) }
                    if (favs.isNotEmpty()) {
                        Text(
                            text = stringResource(R.string.favorites_title),
                            style = MaterialTheme.typography.titleSmall,
                        )
                        favs.forEach { fav ->
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        text = fav.name,
                                        modifier = Modifier
                                            .weight(1f)
                                            .clickable {
                                                val u = Uri.parse(fav.uri)
                                                uriWritable = runCatching {
                                                    context.contentResolver.takePersistableUriPermission(
                                                        u, Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                                                    )
                                                }.isSuccess
                                                runCatching {
                                                    context.contentResolver.takePersistableUriPermission(
                                                        u, Intent.FLAG_GRANT_READ_URI_PERMISSION
                                                    )
                                                }
            mountWritable = uriWritable && Settings.defaultMountWritable(context)
                                                keyfileUris = emptyList()
                                                pickedUri = u
                                                pickedName = fav.name
                                                error = null
                                            },
                                    )
                                    TextButton(onClick = {
                                        renameFavoriteUri = fav.uri
                                        renameFavoriteText = fav.name
                                    }) {
                                        Text(stringResource(R.string.favorites_rename))
                                    }
                                    TextButton(onClick = {
                                        Settings.reorderFavorite(context, fav.uri, 0)
                                        favTick++
                                    }) {
                                        Text(stringResource(R.string.favorites_pin))
                                    }
                                    TextButton(onClick = {
                                        Settings.removeFavorite(context, fav.uri)
                                        favTick++
                                    }) {
                                        Text(stringResource(R.string.favorites_remove))
                                    }
                                }
                            }
                        }
                    }
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
                                    AutoLock.touch()
                                    Settings.addFavorite(context, uri.toString(), pickedName)
                                    favTick++
                                    // F4：解锁成功请求通知权限，保活前台服务通知才能显示（Android 13+）。
                                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                                        notifPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                                    }
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

                    // 改密码入口（B1）：写操作，仅拿到写权限时可用。旧凭据取上方已填的
                    // 密码 / PIM / PRF / keyfile；点开对话框收集新凭据。
                    if (uriWritable) {
                        TextButton(
                            onClick = { changePwdMsg = null; showChangePwd = true },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.change_pwd_entry))
                        }
                    }

                    // 创建隐藏卷入口（C2）：写操作，仅拿到写权限时可用。在选中的外层容器内
                    // 造隐藏卷；上方已填的密码 / PIM / PRF / keyfile 作外层凭据（读外层 FAT 算安全区），
                    // 点开对话框收集隐藏卷新凭据。
                    if (uriWritable) {
                        TextButton(
                            onClick = { createHiddenMsg = null; showCreateHidden = true },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.create_hidden_entry))
                        }

                        // 卷扩展入口（X17）：写操作，仅拿到写权限时可用。主密钥不动，换头+扩文件。
                        TextButton(
                            onClick = {
                                expandMsg = null; expandSizeMb = ""
                                val u = pickedUri
                                if (u != null) {
                                    scope.launch {
                                        val sz = withContext(Dispatchers.IO) {
                                            runCatching {
                                                context.contentResolver.openFileDescriptor(u, "r")?.use { it.statSize }
                                            }.getOrNull()
                                        }
                                        expandCurrentSize = sz
                                        showExpandVolume = true
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.expand_volume_entry))
                        }
                        TextButton(
                            onClick = { showRescueManager = true },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.rescue_entry))
                        }
                    }

                    // 卷头工具入口（A2 救砖）：低调 TextButton，主头损坏打不开时的最后一道保险。
                    TextButton(
                        onClick = { headerMsg = null; showHeaderTool = true },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.header_tool_entry))
                    }
                    // 分区加密探针入口（X2/X3，实验性）：root-gated 只读枚举块设备。
                    TextButton(
                        onClick = {
                            blockDeviceMsg = null
                            showBlockDevice = true
                            scope.launch {
                                blockDeviceBusy = true
                                val granted = withContext(Dispatchers.IO) { com.henglie.sealchest.core.RootManager.isGranted() }
                                blockDeviceRootGranted = granted
                                if (granted) {
                                    blockDeviceList = withContext(Dispatchers.IO) { com.henglie.sealchest.core.BlockDeviceEnumerator.list() }
                                }
                                blockDeviceBusy = false
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.block_device_entry))
                    }
                    // F3：暴露到系统入口。已挂载 + root 已授权时才显示。
                    if (MountManager.isMounted && com.henglie.sealchest.core.RootManager.isGranted()) {
                        TextButton(
                            onClick = { showExpose = true; exposeMsg = null },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.expose_title))
                        }
                    }
                }
            }
        }
        }

        if (showSettings) SettingsDialog(onDismiss = { showSettings = false })

        // 收藏项重命名弹窗（X9）。
        if (renameFavoriteUri != null) {
            AlertDialog(
                onDismissRequest = { renameFavoriteUri = null },
                title = { Text(stringResource(R.string.favorites_rename_title)) },
                text = {
                    OutlinedTextField(
                        value = renameFavoriteText,
                        onValueChange = { renameFavoriteText = it },
                        label = { Text(stringResource(R.string.favorites_rename_hint)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                },
                confirmButton = {
                    TextButton(onClick = {
                        val u = renameFavoriteUri
                        if (u != null && renameFavoriteText.isNotBlank()) {
                            Settings.renameFavorite(context, u, renameFavoriteText.trim())
                            favTick++
                        }
                        renameFavoriteUri = null
                    }) { Text(stringResource(R.string.ok)) }
                },
                dismissButton = {
                    TextButton(onClick = { renameFavoriteUri = null }) { Text(stringResource(R.string.cancel)) }
                },
            )
        }

        // 卷头工具弹窗（A2）：导出备份 + 从内嵌备份头救砖。
        if (showHeaderTool) {
            HeaderToolDialog(
                busy = headerBusy,
                message = headerMsg,
                canRescue = uriWritable,
                onExport = {
                    exportHeaderLauncher.launch("${pickedName}.scheader")
                },
                onRescue = {
                    rescueLauncher.launch("${pickedName}.rescue.scheader")
                },
                onDismiss = { if (!headerBusy) { showHeaderTool = false; headerMsg = null } },
            )
        }

        // 改密码弹窗（B1）：收集新口令/PIM/PRF/keyfile，确认后先选救援文件再执行。
        if (showChangePwd) {
            ChangePasswordDialog(
                busy = changePwdBusy,
                message = changePwdMsg,
                newPassword = newPassword,
                onNewPasswordChange = { newPassword = it; changePwdMsg = null },
                newPim = newPim,
                onNewPimChange = { newPim = it.filter(Char::isDigit); changePwdMsg = null },
                newPrfIndex = newPrfIndex,
                onNewPrfChange = { newPrfIndex = it },
                newKeyfileCount = newKeyfileUris.size,
                onPickNewKeyfiles = { newKeyfilePicker.launch(arrayOf("*/*")) },
                onClearNewKeyfiles = { newKeyfileUris = emptyList() },
                onConfirm = { changePwdLauncher.launch("${pickedName}.rescue.scheader") },
                onDismiss = {
                    if (!changePwdBusy) {
                        showChangePwd = false; changePwdMsg = null
                        newPassword = ""; newPim = ""; newKeyfileUris = emptyList()
                    }
                },
            )
        }

        // 救援文件管理：列出 app 私有目录自动兜底的旧头组备份，可删（旧密码可解密，安全敏感）。
        if (showRescueManager) {
            RescueManagerDialog(
                context = context,
                onDismiss = { showRescueManager = false },
            )
        }

        // 创建隐藏卷弹窗（C2）：外层凭据取解锁区，隐藏卷凭据在此对话框收集。
        if (showCreateHidden) {
            CreateHiddenVolumeDialog(
                busy = createHiddenBusy,
                message = createHiddenMsg,
                hiddenPassword = hiddenPassword,
                onHiddenPasswordChange = { hiddenPassword = it; createHiddenMsg = null },
                sizeMb = hiddenSizeMb,
                onSizeChange = { hiddenSizeMb = it.filter(Char::isDigit); createHiddenMsg = null },
                algoIndex = hiddenAlgoIndex,
                onAlgoChange = { hiddenAlgoIndex = it },
                prfIndex = hiddenPrfIndex,
                onPrfChange = { hiddenPrfIndex = it },
                pim = hiddenPimText,
                onPimChange = { hiddenPimText = it.filter(Char::isDigit); createHiddenMsg = null },
                hiddenKeyfileCount = hiddenKeyfileUris.size,
                onPickHiddenKeyfiles = { hiddenKeyfilePicker.launch(arrayOf("*/*")) },
                onClearHiddenKeyfiles = { hiddenKeyfileUris = emptyList() },
                onConfirm = runCreateHidden,
                onDismiss = {
                    if (!createHiddenBusy) {
                        showCreateHidden = false; createHiddenMsg = null
                        hiddenPassword = ""; hiddenSizeMb = ""; hiddenPimText = ""
                        hiddenKeyfileUris = emptyList()
                    }
                },
            )
        }
        // 卷扩展弹窗（X17）：原凭据取解锁区，对话框只收新总大小。
        if (showExpandVolume) {
            ExpandVolumeDialog(
                busy = expandBusy,
                message = expandMsg,
                currentSize = expandCurrentSize,
                sizeMb = expandSizeMb,
                onSizeChange = { expandSizeMb = it.filter(Char::isDigit); expandMsg = null },
                onConfirm = { expandLauncher.launch("${pickedName}.expand.rescue.scheader") },
                onDismiss = {
                    if (!expandBusy) {
                        showExpandVolume = false; expandMsg = null
                        expandSizeMb = ""; expandCurrentSize = null
                    }
                },
            )
        }
        // 分区加密探针弹窗（X2/X3，实验性）：root-gated 只读枚举块设备。
        if (showBlockDevice) {
            BlockDeviceDialog(
                busy = blockDeviceBusy,
                message = blockDeviceMsg,
                devices = blockDeviceList,
                rootGranted = blockDeviceRootGranted,
                onRequestRoot = {
                    scope.launch {
                        blockDeviceBusy = true
                        val ok = withContext(Dispatchers.IO) { com.henglie.sealchest.core.RootManager.requestRoot() }
                        blockDeviceRootGranted = ok
                        if (ok) {
                            blockDeviceList = withContext(Dispatchers.IO) { com.henglie.sealchest.core.BlockDeviceEnumerator.list() }
                        }
                        blockDeviceBusy = false
                    }
                },
                onDismiss = {
                    if (!blockDeviceBusy) { showBlockDevice = false; blockDeviceMsg = null }
                },
                onUnlockDevice = { dev ->
                    blockDeviceUnlockTarget = dev
                    blockDeviceUnlockPwd = ""
                },
            )
        }
        // F2：块设备解锁密码输入框。确认后调 BlockDeviceUnlocker.unlock。
        if (blockDeviceUnlockTarget != null) {
            val target = blockDeviceUnlockTarget!!
            AlertDialog(
                onDismissRequest = {
                    if (!blockDeviceBusy) { blockDeviceUnlockTarget = null; blockDeviceUnlockPwd = ""; blockDeviceUnlockWritable = false }
                },
                confirmButton = {
                    TextButton(
                        enabled = !blockDeviceBusy && blockDeviceUnlockPwd.isNotEmpty(),
                        onClick = {
                            scope.launch {
                                blockDeviceBusy = true
                                blockDeviceMsg = null
                                try {
                                    val pwd = blockDeviceUnlockPwd.toByteArray(Charsets.UTF_8)
                                    val mount = withContext(Dispatchers.IO) {
                                        com.henglie.sealchest.core.BlockDeviceUnlocker.unlock(
                                            context = context,
                                            devicePath = target.path,
                                            password = pwd,
                                            writable = blockDeviceUnlockWritable,
                                        )
                                    }
                                    pwd.fill(0)
                                    blockDeviceMsg = context.getString(R.string.block_device_unlocked, target.name)
                                    // 解锁成功：这里只展示成功，不解密卷内容到 UI（F2 只做解锁，不接 UI 浏览）
                                    runCatching { mount.close() }
                                    blockDeviceUnlockTarget = null
                                    blockDeviceUnlockPwd = ""
                                } catch (t: Throwable) {
                                    blockDeviceMsg = context.getString(R.string.block_device_unlock_failed, t.message ?: "?")
                                } finally {
                                    blockDeviceBusy = false
                                }
                            }
                        },
                    ) { Text(stringResource(R.string.block_device_unlock)) }
                },
                dismissButton = {
                    TextButton(onClick = { blockDeviceUnlockTarget = null; blockDeviceUnlockPwd = "" }, enabled = !blockDeviceBusy) {
                        Text(stringResource(R.string.cancel))
                    }
                },
                title = { Text(stringResource(R.string.block_device_unlock) + " · " + target.name) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(target.path, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (blockDeviceBusy) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                                Text("  " + stringResource(R.string.block_device_unlocking))
                            }
                        }
                        OutlinedTextField(
                            value = blockDeviceUnlockPwd,
                            onValueChange = { blockDeviceUnlockPwd = it },
                            label = { Text(stringResource(R.string.unlock_password)) },
                            singleLine = true,
                            visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                            enabled = !blockDeviceBusy,
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            androidx.compose.material3.Checkbox(
                                checked = blockDeviceUnlockWritable,
                                onCheckedChange = { blockDeviceUnlockWritable = it },
                                enabled = !blockDeviceBusy,
                            )
                            Text(stringResource(R.string.mount_writable_on))
                        }
                        if (blockDeviceMsg != null) {
                            Text(blockDeviceMsg!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                },
            )
        }
        // F3：暴露到系统弹窗。root-gated，把已挂载卷明文同步到目录。
        if (showExpose) {
            AlertDialog(
                onDismissRequest = { if (!exposeBusy) { showExpose = false; exposeMsg = null } },
                confirmButton = {
                    TextButton(
                        enabled = !exposeBusy && exposeDir.isNotEmpty(),
                        onClick = {
                            scope.launch {
                                exposeBusy = true
                                exposeMsg = null
                                try {
                                    val target = java.io.File(exposeDir)
                                    val count = withContext(Dispatchers.IO) {
                                        com.henglie.sealchest.core.SystemMounter.syncExpose(target) { path ->
                                            exposeMsg = context.getString(R.string.expose_progress, path)
                                        }
                                    }
                                    exposeMsg = context.getString(R.string.expose_done, count)
                                } catch (t: Throwable) {
                                    exposeMsg = context.getString(R.string.expose_failed, t.message ?: "?")
                                } finally {
                                    exposeBusy = false
                                }
                            }
                        },
                    ) { Text(stringResource(R.string.expose_start)) }
                },
                dismissButton = {
                    Row {
                        TextButton(
                            onClick = {
                                scope.launch {
                                    exposeBusy = true
                                    try {
                                        withContext(Dispatchers.IO) { com.henglie.sealchest.core.SystemMounter.cleanupExpose(java.io.File(exposeDir)) }
                                        exposeMsg = "cleaned"
                                    } catch (t: Throwable) {
                                        exposeMsg = context.getString(R.string.expose_failed, t.message ?: "?")
                                    } finally { exposeBusy = false }
                                }
                            },
                            enabled = !exposeBusy,
                        ) { Text(stringResource(R.string.expose_cleanup)) }
                        TextButton(onClick = { showExpose = false; exposeMsg = null }, enabled = !exposeBusy) {
                            Text(stringResource(R.string.cancel))
                        }
                    }
                },
                title = { Text(stringResource(R.string.expose_title)) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            stringResource(R.string.expose_warning),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                        OutlinedTextField(
                            value = exposeDir,
                            onValueChange = { exposeDir = it },
                            label = { Text(stringResource(R.string.expose_dir_hint)) },
                            singleLine = true,
                            enabled = !exposeBusy,
                        )
                        if (exposeBusy) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                            }
                        }
                        if (exposeMsg != null) {
                            Text(exposeMsg!!, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                },
            )
        }
    }
}

/**
 * 卷头工具弹窗（A2 救砖）。两个动作：
 * - 导出卷头备份：只读容器，把 128KB 主头组转储到文件。平时备份，最安全。
 * - 从内嵌备份头救砖：用卷尾备份头覆盖主头。需密码/keyfile 验证 + 写权限，
 *   覆盖前强制先存救援文件（可逆兜底）。危险操作，文案强提示。
 *
 * [canRescue] = 容器 URI 是否拿到写权限（无写权限只能导出、不能救砖）。
 */
@Composable
private fun HeaderToolDialog(
    busy: Boolean,
    message: String?,
    canRescue: Boolean,
    onExport: () -> Unit,
    onRescue: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = !busy) {
                Text(stringResource(R.string.header_tool_close))
            }
        },
        title = { Text(stringResource(R.string.header_tool_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    stringResource(R.string.header_tool_desc),
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedButton(
                    onClick = onExport,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.header_export_button))
                }
                Text(
                    stringResource(R.string.header_rescue_warn),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                Button(
                    onClick = onRescue,
                    enabled = !busy && canRescue,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (canRescue) stringResource(R.string.header_rescue_button)
                        else stringResource(R.string.header_rescue_need_write)
                    )
                }
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                }
                if (message != null) {
                    Text(
                        message,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
    )
}

/** 「关于」弹窗。展示描述、作者、可点项目地址、版本、核心致谢。 */
/**
 * 改密码 / PIM / PRF / keyfile 弹窗（B1）。
 *
 * 旧凭据复用解锁区已填的密码 / PIM / PRF / keyfile（不在此弹窗重复输入）——用户改密码前
 * 本就要先在解锁区填对当前口令。本弹窗只收集**新**口令 / PIM / PRF / keyfile。
 *
 * 确认时先让用户选一个救援文件保存位置（[onConfirm] 触发 CreateDocument），写头前把当前
 * 主头组导出到该文件（可逆兜底）。改密码是写操作，需容器 URI 已授予写权限。
 * 忙碌时禁用全部输入并显示进度；结果 / 错误经 [message] 展示。
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun ChangePasswordDialog(
    busy: Boolean,
    message: String?,
    newPassword: String,
    onNewPasswordChange: (String) -> Unit,
    newPim: String,
    onNewPimChange: (String) -> Unit,
    newPrfIndex: Int,
    onNewPrfChange: (Int) -> Unit,
    newKeyfileCount: Int,
    onPickNewKeyfiles: () -> Unit,
    onClearNewKeyfiles: () -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.change_pwd_title)) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                Text(stringResource(R.string.change_pwd_desc))
                OutlinedTextField(
                    value = newPassword,
                    onValueChange = onNewPasswordChange,
                    label = { Text(stringResource(R.string.change_pwd_new_password)) },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = newPim,
                    onValueChange = onNewPimChange,
                    label = { Text(stringResource(R.string.change_pwd_new_pim)) },
                    singleLine = true,
                    enabled = !busy,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    stringResource(R.string.change_pwd_new_prf),
                    style = MaterialTheme.typography.labelLarge,
                )
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    PRF_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                        FilterChip(
                            selected = newPrfIndex == i,
                            onClick = { if (!busy) onNewPrfChange(i) },
                            label = { Text(stringResource(labelResId)) },
                            modifier = Modifier.widthIn(min = 96.dp),
                        )
                    }
                }
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    OutlinedButton(
                        onClick = onPickNewKeyfiles,
                        enabled = !busy,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(
                            if (newKeyfileCount == 0) stringResource(R.string.change_pwd_new_keyfiles_none)
                            else stringResource(R.string.change_pwd_new_keyfiles_selected, newKeyfileCount)
                        )
                    }
                    if (newKeyfileCount > 0) {
                        TextButton(onClick = onClearNewKeyfiles, enabled = !busy) {
                            Text(stringResource(R.string.unlock_keyfiles_clear))
                        }
                    }
                }
                if (message != null) {
                    Text(
                        message,
                        color = MaterialTheme.colorScheme.primary,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.height(20.dp),
                            strokeWidth = 2.dp,
                        )
                        Text("  " + stringResource(R.string.change_pwd_working))
                    }
                }
            }
        },
        confirmButton = {
            // 空新口令 + 无新 keyfile 不允许（VC 允许纯 keyfile，故有 keyfile 时放开空口令）。
            TextButton(
                onClick = onConfirm,
                enabled = !busy && (newPassword.isNotEmpty() || newKeyfileCount > 0),
            ) {
                Text(stringResource(R.string.change_pwd_submit))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) {
                Text(stringResource(R.string.change_pwd_dismiss))
            }
        },
    )
}

/**
 * 隐藏卷创建对话框（C2）。外层凭据取解锁区已填字段（对话框不再问），这里只收隐藏卷
 * 自己的算法 / PRF / 大小 / 密码 / PIM。确认后 [onConfirm] 触发 HiddenVolumeCreator：
 * 解锁外层读 FAT 算安全区 → 校验不覆盖外层文件 → 写隐藏卷头 → 格式化隐藏 FAT。
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun CreateHiddenVolumeDialog(
    busy: Boolean,
    message: String?,
    hiddenPassword: String,
    onHiddenPasswordChange: (String) -> Unit,
    sizeMb: String,
    onSizeChange: (String) -> Unit,
    algoIndex: Int,
    onAlgoChange: (Int) -> Unit,
    prfIndex: Int,
    onPrfChange: (Int) -> Unit,
    pim: String,
    onPimChange: (String) -> Unit,
    hiddenKeyfileCount: Int,
    onPickHiddenKeyfiles: () -> Unit,
    onClearHiddenKeyfiles: () -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sizeValid = (sizeMb.toLongOrNull() ?: 0L) > 0
    val canCreate = !busy && hiddenPassword.isNotEmpty() && sizeValid
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.create_hidden_title)) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                Text(
                    stringResource(R.string.create_hidden_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Text(stringResource(R.string.create_algorithm), style = MaterialTheme.typography.labelLarge)
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    CREATE_ALGO_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                        FilterChip(
                            selected = algoIndex == i,
                            onClick = { onAlgoChange(i) },
                            label = { Text(stringResource(labelResId)) },
                        )
                    }
                }

                Text(stringResource(R.string.create_prf), style = MaterialTheme.typography.labelLarge)
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    CREATE_PRF_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                        FilterChip(
                            selected = prfIndex == i,
                            onClick = { onPrfChange(i) },
                            label = { Text(stringResource(labelResId)) },
                        )
                    }
                }

                OutlinedTextField(
                    value = sizeMb,
                    onValueChange = onSizeChange,
                    label = { Text(stringResource(R.string.create_hidden_size_mb)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = hiddenPassword,
                    onValueChange = onHiddenPasswordChange,
                    label = { Text(stringResource(R.string.create_hidden_password)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = pim,
                    onValueChange = onPimChange,
                    label = { Text(stringResource(R.string.create_hidden_pim)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )

                // 隐藏卷 keyfile 选择行（C2 增强，对齐桌面 VC）
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    TextButton(onClick = onPickHiddenKeyfiles, enabled = !busy) {
                        Text(if (hiddenKeyfileCount == 0) stringResource(R.string.create_hidden_keyfiles_none) else stringResource(R.string.create_hidden_keyfiles_selected, hiddenKeyfileCount))
                    }
                    if (hiddenKeyfileCount > 0) {
                        TextButton(onClick = onClearHiddenKeyfiles, enabled = !busy) {
                            Text(stringResource(R.string.unlock_keyfiles_clear))
                        }
                    }
                }

                if (message != null) {
                    Text(
                        message,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                        Text("  " + stringResource(R.string.create_hidden_working))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = canCreate) {
                Text(stringResource(R.string.create_hidden_submit))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) {
                Text(stringResource(R.string.create_hidden_cancel))
            }
        },
    )
}

/**
 * 分区加密探针对话框（X2/X3，实验性）。root-gated 只读枚举块设备，不加密不写。
 * 未授权时显示「授予 root」按钮；已授权时列出设备卡片（名称/大小/可移动/路径）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BlockDeviceDialog(
    busy: Boolean,
    message: String?,
    devices: List<com.henglie.sealchest.core.BlockDeviceEnumerator.BlockDevice>,
    rootGranted: Boolean,
    onRequestRoot: () -> Unit,
    onDismiss: () -> Unit,
    onUnlockDevice: (com.henglie.sealchest.core.BlockDeviceEnumerator.BlockDevice) -> Unit = {},
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = !busy) {
                Text(stringResource(R.string.block_device_close))
            }
        },
        title = { Text(stringResource(R.string.block_device_title)) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                Text(
                    stringResource(R.string.block_device_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                        Text("  " + stringResource(R.string.block_device_loading))
                    }
                }
                if (!rootGranted && !busy) {
                    Text(
                        stringResource(R.string.block_device_no_root),
                        color = MaterialTheme.colorScheme.error,
                    )
                    Button(onClick = onRequestRoot, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.block_device_request_root))
                    }
                }
                if (rootGranted && devices.isEmpty() && !busy) {
                    Text(stringResource(R.string.block_device_empty))
                }
                devices.forEach { dev ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(dev.name, style = MaterialTheme.typography.labelLarge)
                            Text(
                                stringResource(R.string.block_device_size, "%.1f MB".format(dev.sizeBytes / 1024.0 / 1024.0)),
                                style = MaterialTheme.typography.bodySmall,
                            )
                            if (dev.isRemovable) {
                                Text(stringResource(R.string.block_device_removable), style = MaterialTheme.typography.bodySmall)
                            }
                            Text(dev.path, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            // F2：解锁此块设备（root-gated，只读）。点击触发解锁流程。
                            if (rootGranted && !busy) {
                                Button(
                                    onClick = { onUnlockDevice(dev) },
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text(stringResource(R.string.block_device_unlock))
                                }
                            }
                        }
                    }
                }
                if (message != null) {
                    Text(message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
    )
}
/**
 * 卷扩展对话框（X17）。原凭据复用解锁区已填的（同改密码），这里只收新总大小。
 * 确认后 [onConfirm] 选救援文件再执行 VolumeExpander：主密钥不动，换头+扩文件。
 * 仅增大不缩小；新总大小须 > 当前总大小。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ExpandVolumeDialog(
    busy: Boolean,
    message: String?,
    currentSize: Long?,
    sizeMb: String,
    onSizeChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val cur = currentSize
    val curText = if (cur != null && cur > 0) "%.1f MB".format(cur / 1024.0 / 1024.0) else "-"
    val newBytes = (sizeMb.toLongOrNull() ?: 0L) * 1024L * 1024L
    val canExpand = !busy && newBytes > 0 && (cur == null || newBytes > cur)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.expand_volume_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    stringResource(R.string.expand_volume_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.expand_volume_current_size, curText),
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = sizeMb,
                    onValueChange = onSizeChange,
                    label = { Text(stringResource(R.string.expand_volume_new_size_mb)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                        Text("  " + stringResource(R.string.expand_volume_working))
                    }
                }
                if (message != null) {
                    Text(message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = canExpand) {
                Text(stringResource(R.string.expand_volume_submit))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) {
                Text(stringResource(R.string.expand_volume_cancel))
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AboutScreen(onBack: () -> Unit) {
    val uriHandler = LocalUriHandler.current
    val projectUrl = "https://github.com/Henglie/Sealchest"
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.about_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.browse_back),
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
                .padding(horizontal = 20.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // ---- 品牌头：无衬线大标题 + 副标题 + 一句话简介，居中 ----
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp, bottom = 4.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = stringResource(R.string.home_title),
                    style = MaterialTheme.typography.displaySmall,
                    color = MaterialTheme.colorScheme.primary,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = stringResource(R.string.home_subtitle),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    text = stringResource(R.string.about_app_desc),
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
            }

            // ---- 基本信息卡：作者 / 项目地址 / 版本。全部竖排，窄屏不挤压 ----
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    AboutRow(
                        label = stringResource(R.string.about_author_label),
                        value = stringResource(R.string.about_author),
                    )
                    // 项目地址：标签在上，可点链接在下（蓝色下划线，点后系统浏览器打开）。
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            text = stringResource(R.string.about_project_label),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            text = projectUrl,
                            style = MaterialTheme.typography.bodyMedium.copy(
                                color = MaterialTheme.colorScheme.primary,
                                textDecoration = TextDecoration.Underline,
                            ),
                            modifier = Modifier.clickable { uriHandler.openUri(projectUrl) },
                        )
                    }
                    AboutRow(
                        label = stringResource(R.string.about_version_label),
                        value = BuildConfig.VERSION_NAME,
                    )
                }
            }

            // ---- 供应链透明卡：上游版本 / commit / 工具链 / ABI + 说明 ----
            // 数据源为 build.gradle.kts 的 buildConfigField，与实际编译绑定，非手写。
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    AboutRow(
                        label = stringResource(R.string.about_upstream_label),
                        value = "VeraCrypt " + BuildConfig.VC_UPSTREAM_VERSION,
                    )
                    AboutRow(
                        label = stringResource(R.string.about_upstream_commit_label),
                        value = BuildConfig.VC_UPSTREAM_COMMIT,
                    )
                    AboutRow(
                        label = stringResource(R.string.about_toolchain_label),
                        value = BuildConfig.BUILD_TOOLCHAIN,
                    )
                    AboutRow(
                        label = stringResource(R.string.about_abis_label),
                        value = BuildConfig.BUILD_ABIS,
                    )
                    Text(
                        text = stringResource(R.string.about_supplychain_note),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            // ---- 致谢与声明 ----
            Text(
                text = stringResource(R.string.about_credit),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
        }
    }
}

/** 关于页信息行：标签在上（次要色小字），值在下——竖排，窄屏不挤压。 */
@Composable
private fun AboutRow(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun MountedPanel(
    mount: com.henglie.sealchest.fs.MountManager.Mount,
    fs: VolumeFs,
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
    var showInfo by remember { mutableStateOf(false) }

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
                stringResource(R.string.mounted_filesystem, fs.fsType),
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

    // 容器信息面板入口（X10）：只读展示算法/PRF/大小/文件系统/卷标等元信息。
    OutlinedButton(onClick = { showInfo = true }, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.info_entry))
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

    // 容器信息弹窗（X10）：只读展示，dismiss 即关。
    if (showInfo) {
        ContainerInfoDialog(
            mount = mount,
            onDismiss = { showInfo = false },
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

/**
 * 容器信息面板（X10）。只读展示挂载卷的加密算法 / PRF / 数据区大小 / 扇区大小 /
 * 文件系统 / 卷标 / 隐藏卷 / 可写状态。全部取自 Mount 的只读快照，不触碰解密路径。
 */
@Composable
private fun ContainerInfoDialog(
    mount: com.henglie.sealchest.fs.MountManager.Mount,
    onDismiss: () -> Unit,
) {
    // stringResource 是 composable 调用，须在 composable 作用域取值；局部函数保持纯计算。
    val cascade = stringResource(R.string.info_cascade)
    val yes = stringResource(R.string.info_yes)
    val no = stringResource(R.string.info_no)
    fun algoName(ea: Int): String = when (ea) {
        1 -> "AES"
        2 -> "Serpent"
        3 -> "Twofish"
        4 -> "Camellia"
        5 -> "Kuznyechik"
        else -> cascade + " (#$ea)"
    }
    fun prfName(p: Int): String = when (p) {
        1 -> "SHA-512"
        2 -> "Whirlpool"
        3 -> "SHA-256"
        4 -> "BLAKE2s"
        5 -> "Streebog"
        else -> "#$p"
    }
    fun humanSize(bytes: Long): String {
        val mb = bytes / 1024.0 / 1024.0
        return if (mb >= 1024) "%.2f GB".format(mb / 1024.0) else "%.1f MB".format(mb)
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.info_close)) }
        },
        title = { Text(stringResource(R.string.info_title)) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                AboutRow(stringResource(R.string.info_algorithm), algoName(mount.encryptionAlgorithm))
                AboutRow(stringResource(R.string.info_prf), prfName(mount.prf))
                AboutRow(stringResource(R.string.info_data_size), stringResource(R.string.info_bytes_fmt, humanSize(mount.dataSize), mount.dataSize))
                AboutRow(stringResource(R.string.info_sector_size), "${mount.sectorSize}")
                AboutRow(stringResource(R.string.info_fs_type), mount.fsType)
                AboutRow(
                    stringResource(R.string.info_label),
                    mount.volumeLabel.ifBlank { stringResource(R.string.mounted_no_label) },
                )
                AboutRow(stringResource(R.string.info_hidden), if (mount.isHidden) yes else no)
                AboutRow(stringResource(R.string.info_writable), if (mount.writable) yes else no)
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

// 自动兜底救援文件：写头前把当前主头组同时留一份到 app 私有目录（filesDir/rescue/，
// 别的 app 读不到、卸载即删）。文件名带容器显示名+时间戳，可复原、可在设置里手动清。
// 安全权衡：救援文件是旧主头组，旧密码可解密还原——即改密后旧密码经此文件仍能开卷。
// 放私有沙盒是移动端对 VC 桌面版救援盘的等价处理。
@Composable
private fun RescueManagerDialog(
    context: android.content.Context,
    onDismiss: () -> Unit,
) {
    val dir = java.io.File(context.filesDir, "rescue")
    var files by remember {
        mutableStateOf(
            (dir.listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList())
        )
    }
    val fmt = remember { java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.getDefault()) }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.rescue_mgr_title)) },
        text = {
            androidx.compose.foundation.layout.Column {
                Text(
                    stringResource(R.string.rescue_mgr_warn),
                    style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                    color = androidx.compose.material3.MaterialTheme.colorScheme.error,
                )
                Spacer(Modifier.height(8.dp))
                if (files.isEmpty()) {
                    Text(stringResource(R.string.rescue_mgr_empty))
                } else {
                    androidx.compose.foundation.lazy.LazyColumn(
                        modifier = Modifier.heightIn(max = 320.dp),
                    ) {
                        items(files.size) { i ->
                            val f = files[i]
                            androidx.compose.foundation.layout.Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                            ) {
                                androidx.compose.foundation.layout.Column(Modifier.weight(1f)) {
                                    Text(f.name, style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
                                    Text(
                                        fmt.format(java.util.Date(f.lastModified())) + "  " + (f.length() / 1024) + " KB",
                                        style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                TextButton(onClick = {
                                    runCatching { f.delete() }
                                    files = dir.listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()
                                }) { Text(stringResource(R.string.rescue_mgr_delete)) }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    files.forEach { runCatching { it.delete() } }
                    files = emptyList()
                },
                enabled = files.isNotEmpty(),
            ) { Text(stringResource(R.string.rescue_mgr_clear_all)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
        },
    )
}

private fun autoRescueFile(context: android.content.Context, uri: Uri): java.io.File {
    val dir = java.io.File(context.filesDir, "rescue").apply { mkdirs() }
    val raw = queryDisplayName(context, uri) ?: "volume"
    val safe = raw.replace(Regex("[^A-Za-z0-9._-]"), "_").take(40)
    return java.io.File(dir, "rescue_" + safe + "_" + System.currentTimeMillis() + ".vcbak")
}
