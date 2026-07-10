package com.henglie.sealchest.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.henglie.sealchest.core.BiometricUnlock
import com.henglie.sealchest.core.PanicManager
import com.henglie.sealchest.core.PinManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * PIN 门禁界面：app 启动时若已设 PIN，显示此界面要求输入 PIN。
 * 验证通过才进主界面。PIN 与容器密码独立，仅作 app 启动门禁。
 *
 * - 全屏 PIN 输入（OutlinedTextField 密码模式，数字键盘）
 * - 错误显示红字提示，不清空输入（让用户改）
 * - 底部「清除 PIN」入口：需先验证当前 PIN 才能清（防他人趁未锁时直接清掉门禁）
 * - **Panic PIN 检测**：输入匹配 Panic PIN 时，不进 app，触发紧急擦除后退出
 * - **生物识别**：[biometricEnabled] 且设备支持时，启动自动弹指纹；指纹图标可再次唤起。
 *   生物识别只解锁门禁，**绝不**触发 Panic 擦除（紧急擦除必须手动输 PIN，防误触）。
 *
 * [onPinCorrect]：验证通过回调（进主界面）。
 * [onClearPin]：用户已验证当前 PIN 并清除后回调（清完门禁进主界面）。
 *
 * Argon2id 派生是重活（64MB / 2 轮），必须跑 IO 线程，避免卡 UI。
 */
@Composable
fun PinGateScreen(
    biometricEnabled: Boolean = false,
    onPinCorrect: () -> Unit,
    onClearPin: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    // 生物识别：宿主需 FragmentActivity（MainActivity 已是）。设备不支持则降级为纯 PIN。
    val activity = context as? FragmentActivity
    val bioAvailable = biometricEnabled && activity != null && BiometricUnlock.canAuthenticate(context)

    fun promptBiometric() {
        val act = activity ?: return
        BiometricUnlock.authenticate(
            activity = act,
            title = "解锁匿匣",
            subtitle = "使用指纹 / 面部解锁 PIN 门禁",
            onSuccess = { onPinCorrect() },
            onError = { msg -> error = msg },
        )
    }

    // 启动时若启用生物识别，自动弹一次（用户取消后不再自动弹，可点指纹图标重试）。
    LaunchedEffect(bioAvailable) {
        if (bioAvailable) promptBiometric()
    }

    // 跑一次 Argon2id 验证，结果交回调。busy 期间禁用所有输入。
    fun verify(then: (ok: Boolean) -> Unit) {
        if (busy || pin.isEmpty()) return
        busy = true
        error = null
        scope.launch {
            val ok = withContext(Dispatchers.IO) { PinManager.verifyPin(context, pin) }
            busy = false
            then(ok)
        }
    }

    // Panic PIN 验证：匹配则触发紧急擦除，UI 假装正常响应（防暴力探测区分）。
    fun checkPanicThen(then: () -> Unit) {
        if (busy || pin.isEmpty()) return
        if (!PanicManager.isPanicPinSet(context)) { then(); return }
        busy = true
        scope.launch {
            val isPanic = withContext(Dispatchers.IO) { PanicManager.verifyPanicPin(context, pin) }
            if (isPanic) {
                // 匹配 Panic PIN → 紧急擦除 → 退出 app。
                withContext(Dispatchers.IO) { PanicManager.executePanicWipe(context) }
                busy = false
                // 用退出进程模拟「app 没反应」，掩盖擦除动作。
                android.os.Process.killProcess(android.os.Process.myPid())
            } else {
                busy = false
                then()
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(Icons.Filled.Lock, contentDescription = null)
        Spacer(Modifier.height(8.dp))
        Text(
            text = "请输入 PIN",
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = pin,
            onValueChange = { pin = it; error = null },
            label = { Text("PIN") },
            singleLine = true,
            enabled = !busy,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            modifier = Modifier.fillMaxWidth(),
        )
        if (error != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                error!!,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = {
                // 先查 Panic PIN（匹配则擦除退出），否则查解锁 PIN。
                checkPanicThen {
                    verify { ok -> if (ok) onPinCorrect() else error = "PIN 错误" }
                }
            },
            enabled = !busy && pin.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier.height(20.dp),
                    strokeWidth = 2.dp,
                )
            } else {
                Text("解锁")
            }
        }
        Spacer(Modifier.height(8.dp))
        // 生物识别入口：启用且设备支持时显示指纹图标，点击重新弹指纹。
        // Panic 不走这里——紧急擦除必须手动输 PIN，防误触。
        if (bioAvailable) {
            IconButton(onClick = { promptBiometric() }) {
                Icon(Icons.Filled.Fingerprint, contentDescription = "指纹解锁")
            }
        }
        // 清除 PIN：需先验证当前 PIN 才能清（防他人趁手机未锁时直接清掉门禁）。
        TextButton(
            onClick = {
                verify { ok ->
                    if (ok) {
                        PinManager.clearPin(context)
                        onClearPin()
                    } else {
                        error = "PIN 错误，无法清除"
                    }
                }
            },
            enabled = !busy && pin.isNotEmpty(),
        ) {
            Text("清除 PIN")
        }
    }
}
