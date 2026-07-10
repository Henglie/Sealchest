package com.henglie.sealchest

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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

/**
 * 设置弹窗：自动锁定配置。改动即写 [Settings]，并 [AutoLock.touch] 让新超时立刻生效。
 * 仅存行为偏好，绝不碰密码/密钥。
 */
@Composable
fun SettingsDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current

    var enabled by remember { mutableStateOf(Settings.autoLockEnabled(context)) }
    var timeoutMs by remember { mutableStateOf(Settings.autoLockTimeoutMs(context)) }
    var lockBg by remember { mutableStateOf(Settings.lockOnBackground(context)) }
    var lockScreenOff by remember { mutableStateOf(Settings.lockOnScreenOff(context)) }
    var timeoutMenuOpen by remember { mutableStateOf(false) }
    var defMountWritable by remember { mutableStateOf(Settings.defaultMountWritable(context)) }
    var defPrfIndex by remember { mutableStateOf(Settings.defaultPrfIndex(context)) }
    var ntfsExp by remember { mutableStateOf(Settings.ntfsExperimental(context)) }
    var pinSet by remember { mutableStateOf(PinManager.isPinSet(context)) }
    var showSetPin by remember { mutableStateOf(false) }
    var showClearPin by remember { mutableStateOf(false) }
    // 生物识别解锁 PIN 门禁（X4）：仅 PIN 已设时生效。
    var biometricEnabled by remember { mutableStateOf(Settings.biometricUnlockEnabled(context)) }
    val biometricSupported = com.henglie.sealchest.core.BiometricUnlock.canAuthenticate(context)
    // Panic PIN（紧急擦除）
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

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.settings_close)) }
        },
        title = { Text(stringResource(R.string.settings_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.settings_autolock_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                // 总开关
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.settings_autolock_enable),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Switch(
                        checked = enabled,
                        onCheckedChange = {
                            enabled = it
                            Settings.setAutoLockEnabled(context, it)
                            AutoLock.touch()
                        },
                    )
                }

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

                // 切后台锁
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.settings_lock_background),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Switch(
                        checked = lockBg,
                        enabled = enabled,
                        onCheckedChange = {
                            lockBg = it
                            Settings.setLockOnBackground(context, it)
                        },
                    )
                }

                // 息屏锁
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.settings_lock_screen_off),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Switch(
                        checked = lockScreenOff,
                        enabled = enabled,
                        onCheckedChange = {
                            lockScreenOff = it
                            Settings.setLockOnScreenOff(context, it)
                        },
                    )
                }

                Spacer(Modifier.height(8.dp))

                // 默认挂载模式（X13）
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.settings_default_mount_writable),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Switch(
                        checked = defMountWritable,
                        onCheckedChange = {
                            defMountWritable = it
                            Settings.setDefaultMountWritable(context, it)
                        },
                    )
                }

                // 默认 PRF（X13）
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

                Spacer(Modifier.height(8.dp))

                // NTFS 实验开关（默认关）：开启才允许挂 NTFS 容器（读写待真机 chkdsk 验收）。
                Text(
                    stringResource(R.string.settings_ntfs_exp_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.settings_ntfs_exp),
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Switch(
                        checked = ntfsExp,
                        onCheckedChange = {
                            ntfsExp = it
                            Settings.setNtfsExperimental(context, it)
                        },
                    )
                }

                // ---- PIN 锁（app 启动门禁，对标 Arcanum）----
                Spacer(Modifier.height(8.dp))
                Text(
                    "PIN 锁",
                    style = MaterialTheme.typography.labelLarge,
                )
                Text(
                    if (pinSet) "已设置：启动 app 需输入 PIN" else "未设置：启动 app 直接进入",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
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

                // 生物识别解锁（仅 PIN 已设 + 设备支持时可用）
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        "生物识别解锁",
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Switch(
                        checked = biometricEnabled,
                        enabled = pinSet && biometricSupported,
                        onCheckedChange = {
                            biometricEnabled = it
                            Settings.setBiometricUnlockEnabled(context, it)
                        },
                    )
                }
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

                // ---- Panic PIN（紧急擦除，对标 Arcanum panic mode）----
                Spacer(Modifier.height(8.dp))
                Text(
                    "Panic PIN（紧急擦除）",
                    style = MaterialTheme.typography.labelLarge,
                )
                Text(
                    if (panicSet) "已设置：输入此 PIN 触发擦除（容器上锁+收藏清空+PIN 清除）"
                    else "未设置：输入此 PIN 立即擦除 app 数据并退出",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
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
        },
    )

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
