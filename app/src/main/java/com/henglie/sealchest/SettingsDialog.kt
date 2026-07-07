package com.henglie.sealchest

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.henglie.sealchest.core.AutoLock
import com.henglie.sealchest.core.Settings

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
            }
        },
    )
}
