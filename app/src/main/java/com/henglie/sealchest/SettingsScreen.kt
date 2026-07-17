package com.henglie.sealchest

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.henglie.sealchest.core.AutoLock
import com.henglie.sealchest.core.PinManager
import com.henglie.sealchest.core.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** 主题色预设：(ARGB, 显示名)。默认酒红排第一，与 Settings.themeColor 默认值一致。 */
private val THEME_COLOR_OPTIONS: List<Pair<Int, String>> = listOf(
    0 to "跟随系统",
    0xFF8B2D35.toInt() to "酒红",
    0xFF1A5276.toInt() to "深蓝",
    0xFF1E5631.toInt() to "森林绿",
    0xFF6C3483.toInt() to "紫罗兰",
    0xFFB7950B.toInt() to "琥珀",
    0xFF2C3E50.toInt() to "炭灰",
)

/**
 * 设置独立界面（全屏 Scaffold + 分类 Card）。替代原 [SettingsDialog] 弹窗——
 * 弹窗内控件太多太挤，改全屏滚动后每组用 Card 分隔，呼吸感更好。
 *
 * 分类：自动锁定 / PIN 门禁 / Panic PIN / 挂载偏好 / 高级。
 * 子对话框（SetPin/ClearPin/SetPanic/ClearPanic）仍用 AlertDialog，逻辑不变。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current

    var enabled by remember { mutableStateOf(Settings.autoLockEnabled(context)) }
    var timeoutMs by remember { mutableStateOf(Settings.autoLockTimeoutMs(context)) }
    var lockBg by remember { mutableStateOf(Settings.lockOnBackground(context)) }
    var lockScreenOff by remember { mutableStateOf(Settings.lockOnScreenOff(context)) }
    var timeoutMenuOpen by remember { mutableStateOf(false) }
    var defMountWritable by remember { mutableStateOf(Settings.defaultMountWritable(context)) }
    var defPrfIndex by remember { mutableStateOf(Settings.defaultPrfIndex(context)) }
    var currentThemeColor by remember { mutableStateOf(Settings.themeColor(context)) }
    var currentThemeMode by remember { mutableStateOf(Settings.themeMode(context)) }
    var pinSet by remember { mutableStateOf(PinManager.isPinSet(context)) }
    var showSetPin by remember { mutableStateOf(false) }
    var showClearPin by remember { mutableStateOf(false) }
    var biometricEnabled by remember { mutableStateOf(Settings.biometricUnlockEnabled(context)) }
    val biometricSupported = com.henglie.sealchest.core.BiometricUnlock.canAuthenticate(context)
    var panicSet by remember { mutableStateOf(com.henglie.sealchest.core.PanicManager.isPanicPinSet(context)) }
    var showSetPanic by remember { mutableStateOf(false) }
    var showClearPanic by remember { mutableStateOf(false) }
    var prfMenuOpen by remember { mutableStateOf(false) }
    val prfLabels = listOf(
        R.string.prf_auto, R.string.prf_sha512, R.string.prf_whirlpool,
        R.string.prf_sha256, R.string.prf_blake2s, R.string.prf_streebog,
    )

    fun timeoutLabel(ms: Long): String =
        Settings.TIMEOUT_OPTIONS.firstOrNull { it.first == ms }?.second ?: "$ms ms"

    // Batch self-test state: running / progress / result summary.
    val batchScope = rememberCoroutineScope()
    var batchRunning by remember { mutableStateOf(false) }
    var batchProgress by remember { mutableStateOf("") }
    var batchResult by remember { mutableStateOf<String?>(null) }
    val batchDirLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            }
            batchRunning = true
            batchResult = null
            batchProgress = "..."
            batchScope.launch {
                val r = withContext(Dispatchers.IO) {
                    com.henglie.sealchest.fs.VolumeBatchTest.runFullBatch(context, uri) { msg ->
                        batchProgress = msg
                    }
                }
                batchRunning = false
                batchResult = r.summary()
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    androidx.compose.material3.IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
            )
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Spacer(Modifier.height(8.dp))

            // ===== 自动锁定 =====
            SettingsCard(title = stringResource(R.string.settings_autolock_enable)) {
                Text(
                    stringResource(R.string.settings_autolock_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                SettingsSwitchRow(
                    label = stringResource(R.string.settings_autolock_enable),
                    checked = enabled,
                    onCheckedChange = {
                        enabled = it
                        Settings.setAutoLockEnabled(context, it)
                        AutoLock.touch()
                    },
                )
                // 超时档位
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.settings_autolock_timeout),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedButton(onClick = { timeoutMenuOpen = true }, enabled = enabled) {
                        Text(timeoutLabel(timeoutMs))
                    }
                    DropdownMenu(
                        expanded = timeoutMenuOpen,
                        onDismissRequest = { timeoutMenuOpen = false },
                    ) {
                        Settings.TIMEOUT_OPTIONS.forEach { (ms, label) ->
                            DropdownMenuItem(
                                text = { Text(label) },
                                onClick = {
                                    timeoutMs = ms
                                    Settings.setAutoLockTimeoutMs(context, ms)
                                    timeoutMenuOpen = false
                                    AutoLock.touch()
                                },
                            )
                        }
                    }
                }
                SettingsSwitchRow(
                    label = stringResource(R.string.settings_lock_background),
                    checked = lockBg,
                    enabled = enabled,
                    onCheckedChange = {
                        lockBg = it
                        Settings.setLockOnBackground(context, it)
                    },
                )
                SettingsSwitchRow(
                    label = stringResource(R.string.settings_lock_screen_off),
                    checked = lockScreenOff,
                    enabled = enabled,
                    onCheckedChange = {
                        lockScreenOff = it
                        Settings.setLockOnScreenOff(context, it)
                    },
                )
            }

            // ===== PIN 门禁 =====
            SettingsCard(title = "PIN") {
                Text(
                    if (pinSet) "已设置：启动 app 需输入 PIN" else "未设置：启动 app 直接进入",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = { showSetPin = true },
                        modifier = Modifier.weight(1f),
                    ) { Text(if (pinSet) "修改 PIN" else "设置 PIN") }
                    if (pinSet) {
                        OutlinedButton(
                            onClick = { showClearPin = true },
                            modifier = Modifier.weight(1f),
                        ) { Text("清除 PIN") }
                    }
                }
                Spacer(Modifier.height(4.dp))
                SettingsSwitchRow(
                    label = "生物识别解锁",
                    checked = biometricEnabled,
                    enabled = pinSet && biometricSupported,
                    onCheckedChange = {
                        biometricEnabled = it
                        Settings.setBiometricUnlockEnabled(context, it)
                    },
                )
                Text(
                    when {
                        !pinSet -> "需先设置 PIN 才能启用生物识别"
                        !biometricSupported -> "设备未录入指纹/面部或不支持"
                        biometricEnabled -> "启动 app 可用指纹/面部解锁门禁（Panic PIN 仍需手动输）"
                        else -> "关闭：每次启动需手动输 PIN"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // ===== Panic PIN =====
            SettingsCard(title = "Panic PIN") {
                Text(
                    if (panicSet) "已设置：输入此 PIN 触发擦除（容器上锁+收藏清空+PIN 清除）"
                    else "未设置：输入此 PIN 立即擦除 app 数据并退出",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = { showSetPanic = true },
                        modifier = Modifier.weight(1f),
                    ) { Text(if (panicSet) "修改 Panic PIN" else "设置 Panic PIN") }
                    if (panicSet) {
                        OutlinedButton(
                            onClick = { showClearPanic = true },
                            modifier = Modifier.weight(1f),
                        ) { Text("清除 Panic PIN") }
                    }
                }
            }

            // ===== 挂载偏好 =====
            SettingsCard(title = stringResource(R.string.settings_default_mount_writable)) {
                SettingsSwitchRow(
                    label = stringResource(R.string.settings_default_mount_writable),
                    checked = defMountWritable,
                    onCheckedChange = {
                        defMountWritable = it
                        Settings.setDefaultMountWritable(context, it)
                    },
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.settings_default_prf),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedButton(onClick = { prfMenuOpen = true }) {
                        Text(stringResource(prfLabels[defPrfIndex]))
                    }
                    DropdownMenu(
                        expanded = prfMenuOpen,
                        onDismissRequest = { prfMenuOpen = false },
                    ) {
                        prfLabels.forEachIndexed { idx, res ->
                            DropdownMenuItem(
                                text = { Text(stringResource(res)) },
                                onClick = {
                                    defPrfIndex = idx
                                    Settings.setDefaultPrfIndex(context, idx)
                                    prfMenuOpen = false
                                },
                            )
                        }
                    }
                }
            }

            // ===== 夜间模式 =====
            SettingsCard(title = stringResource(R.string.settings_theme_mode)) {
                val modeLabels = listOf(
                    stringResource(R.string.lang_follow_system),
                    stringResource(R.string.theme_mode_light),
                    stringResource(R.string.theme_mode_dark),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    modeLabels.forEachIndexed { idx, label ->
                        val selected = idx == currentThemeMode
                        OutlinedButton(
                            onClick = {
                                currentThemeMode = idx
                                Settings.setThemeMode(context, idx)
                                (context as? Activity)?.recreate()
                            },
                            modifier = Modifier.weight(1f),
                            colors = if (selected)
                                androidx.compose.material3.ButtonDefaults.outlinedButtonColors(
                                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                                )
                            else androidx.compose.material3.ButtonDefaults.outlinedButtonColors(),
                        ) {
                            Text(label, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            // ===== 主题色 =====
            //   argb==0 = 跟随系统（动态取色 / 兜底整套一致，不叠加固定色）。该 swatch 用当前
            //   primary 实色圈 + 内环标记表示「随系统」；其余项用各自预设纯色。
            SettingsCard(title = stringResource(R.string.settings_theme_color)) {
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    THEME_COLOR_OPTIONS.forEach { (argb, _) ->
                        val selected = argb == currentThemeColor
                        val followSystem = argb == 0
                        val swatchColor =
                            if (followSystem) MaterialTheme.colorScheme.primary else Color(argb)
                        Box(
                            contentAlignment = Alignment.Center,
                            modifier = Modifier
                                .size(40.dp)
                                .clip(CircleShape)
                                .background(swatchColor)
                                .clickable {
                                    currentThemeColor = argb
                                    Settings.setThemeColor(context, argb)
                                    (context as? Activity)?.recreate()
                                }
                                .then(
                                    if (selected) Modifier.border(2.dp, MaterialTheme.colorScheme.onSurface, CircleShape)
                                    else Modifier
                                ),
                        ) {
                            // 「跟随系统」项：内画一个空心环，区别于纯预设色实心圈。
                            if (followSystem) {
                                Box(
                                    modifier = Modifier
                                        .size(16.dp)
                                        .clip(CircleShape)
                                        .background(MaterialTheme.colorScheme.surface)
                                )
                            }
                        }
                    }
                }
            }

            SettingsCard(title = "Batch Self-Test / 一键批量自检") {
                Text(
                    "Auto-create FAT/exFAT/NTFS x all cluster sizes (27) plus VC feature variants " +
                        "(keyfile / multi-keyfile / Serpent / Twofish / SHA-256 / PIM / dynamic / hidden, 10) = 37 containers " +
                        "in a chosen folder, mount each writable and run full read/write cases. Containers stay for desktop VeraCrypt + chkdsk re-verification.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (batchRunning) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                        Text(batchProgress, style = MaterialTheme.typography.bodySmall)
                    }
                } else {
                    OutlinedButton(
                        onClick = { batchDirLauncher.launch(null) },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Choose folder & start / 选择文件夹开始") }
                }
                if (batchResult != null) {
                    Text(
                        batchResult!!,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

        }
    }

    // ---- 子对话框（逻辑不变，从原 SettingsDialog 平移）----
    if (showSetPin) {
        SetPinDialog(
            onDismiss = { showSetPin = false },
            onDone = {
                pinSet = PinManager.isPinSet(context)
                showSetPin = false
            },
        )
    }
    if (showClearPin) {
        ClearPinDialog(
            onDismiss = { showClearPin = false },
            onDone = {
                pinSet = false
                showClearPin = false
            },
        )
    }
    if (showSetPanic) {
        SetPanicDialog(
            onDismiss = { showSetPanic = false },
            onDone = {
                panicSet = com.henglie.sealchest.core.PanicManager.isPanicPinSet(context)
                showSetPanic = false
            },
        )
    }
    if (showClearPanic) {
        ClearPanicDialog(
            onDismiss = { showClearPanic = false },
            onDone = {
                panicSet = false
                showClearPanic = false
            },
        )
    }
}

/** 设置页分组卡片：标题 + 内容块。 */
@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
            )
            content()
        }
    }
}

/** 设置行：左标签 + 右开关。 */
@Composable
private fun SettingsSwitchRow(
    label: String,
    checked: Boolean,
    enabled: Boolean = true,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
        )
        Switch(checked = checked, enabled = enabled, onCheckedChange = onCheckedChange)
    }
}

// ===== 以下子对话框从原 SettingsDialog.kt 平移，逻辑不变 =====

/**
 * 设置 / 修改 PIN 对话框。收集新 PIN + 确认，一致才提交。覆盖旧 PIN。
 * Argon2id 派生跑 IO 线程，忙碌时禁用输入。
 */
@Composable
private fun SetPinDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val mismatch = pin.isNotEmpty() && confirm.isNotEmpty() && pin != confirm
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("设置 PIN") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "PIN 用于 app 启动门禁，与容器密码独立。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    label = { Text("新 PIN") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    label = { Text("确认 PIN") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (mismatch) {
                    Text(
                        "两次输入不一致",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && pin.isNotEmpty() && pin == confirm,
                onClick = {
                    busy = true
                    val v = pin
                    scope.launch {
                        withContext(Dispatchers.IO) { PinManager.setPin(context, v) }
                        busy = false
                        onDone()
                    }
                },
            ) { Text("确定") }
        },
        dismissButton = {
            TextButton(onClick = { if (!busy) onDismiss() }, enabled = !busy) { Text("取消") }
        },
    )
}

/**
 * 清除 PIN 对话框。需先验证当前 PIN 才能清（防他人趁未锁时直接清掉门禁）。
 * Argon2id 验证跑 IO 线程。
 */
@Composable
private fun ClearPinDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("清除 PIN") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "需验证当前 PIN 才能清除。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it; error = null },
                    label = { Text("当前 PIN") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                    }
                }
                if (error != null) {
                    Text(
                        error!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && pin.isNotEmpty(),
                onClick = {
                    busy = true
                    error = null
                    val v = pin
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) { PinManager.verifyPin(context, v) }
                        busy = false
                        if (ok) {
                            PinManager.clearPin(context)
                            onDone()
                        } else {
                            error = "PIN 错误"
                        }
                    }
                },
            ) { Text("清除") }
        },
        dismissButton = {
            TextButton(onClick = { if (!busy) onDismiss() }, enabled = !busy) { Text("取消") }
        },
    )
}

/**
 * 设置 / 修改 Panic PIN 对话框。收集新 PIN + 确认，一致才提交。覆盖旧 Panic PIN。
 * Argon2id 派生跑 IO 线程，忙碌时禁用输入。
 *
 * Panic PIN 与解锁 PIN 独立：输入此 PIN 不解锁，而是触发紧急擦除（容器上锁 +
 * 收藏清空 + PIN 清除 + 缓存清空）后退出 app。
 */
@Composable
private fun SetPanicDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val mismatch = pin.isNotEmpty() && confirm.isNotEmpty() && pin != confirm
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("设置 Panic PIN") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Panic PIN 触发紧急擦除：容器上锁 + 收藏清空 + PIN 清除 + 缓存清空，然后退出 app。与解锁 PIN 独立。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it },
                    label = { Text("新 Panic PIN") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    label = { Text("确认 Panic PIN") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (mismatch) {
                    Text(
                        "两次输入不一致",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && pin.isNotEmpty() && pin == confirm,
                onClick = {
                    busy = true
                    val v = pin
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            com.henglie.sealchest.core.PanicManager.setPanicPin(context, v)
                        }
                        busy = false
                        onDone()
                    }
                },
            ) { Text("确定") }
        },
        dismissButton = {
            TextButton(onClick = { if (!busy) onDismiss() }, enabled = !busy) { Text("取消") }
        },
    )
}

/**
 * 清除 Panic PIN 对话框。需先验证当前 Panic PIN 才能清。
 * Argon2id 验证跑 IO 线程。
 */
@Composable
private fun ClearPanicDialog(onDismiss: () -> Unit, onDone: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("清除 Panic PIN") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "需验证当前 Panic PIN 才能清除。注意：输入正确会清除 Panic PIN，不会触发擦除。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it; error = null },
                    label = { Text("当前 Panic PIN") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (busy) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                    }
                }
                if (error != null) {
                    Text(
                        error!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && pin.isNotEmpty(),
                onClick = {
                    busy = true
                    error = null
                    val v = pin
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) {
                            com.henglie.sealchest.core.PanicManager.verifyPanicPin(context, v)
                        }
                        busy = false
                        if (ok) {
                            com.henglie.sealchest.core.PanicManager.clearPanicPin(context)
                            onDone()
                        } else {
                            error = "Panic PIN 错误"
                        }
                    }
                },
            ) { Text("清除") }
        },
        dismissButton = {
            TextButton(onClick = { if (!busy) onDismiss() }, enabled = !busy) { Text("取消") }
        },
    )
}
