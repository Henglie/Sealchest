package com.henglie.sealchest.core

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * 生物识别解锁封装。仅用于 PIN 门禁的便捷解锁，绝不参与容器密码。
 *
 * 对标 EDS/Arcanum：已设 PIN 且开启生物识别时，启动 app 可直接用指纹/面部
 * 解锁门禁，免输 PIN。
 *
 * 安全红线：
 *  - 只用 BIOMETRIC_STRONG（Class 3），弱生物识别不够安全。
 *  - Panic PIN 不走生物识别：紧急擦除必须手动输 PIN，防误触。
 *  - 生物识别失败/取消不影响 PIN 输入入口，用户随时可 fallback 手动输 PIN。
 *
 * BiometricPrompt 要求宿主是 [FragmentActivity]（MainActivity 已改为其子类）。
 */
object BiometricUnlock {

    /** 设备是否支持强生物识别且已录入指纹/面部。 */
    fun canAuthenticate(context: Context): Boolean {
        val bm = BiometricManager.from(context)
        return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * 弹出系统生物识别对话框。
     *
     * [onSuccess]：验证通过（→ 进主界面）。
     * [onError]：用户取消 / 错误次数过多 / 设备异常（带文案，UI 可提示或忽略）。
     *
     * 认证失败（指纹不匹配）由系统自行重试并提示，不回调 [onError]——只有
     * 不可恢复的错误（如用户点「取消」）才回调，避免一次按错就关掉入口。
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String? = null,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onSuccess()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onError(errString.toString())
            }
            // onAuthenticationFailed（指纹不匹配）不重写：交给系统重试提示。
        }
        val prompt = BiometricPrompt(activity, executor, callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .apply { subtitle?.let { setSubtitle(it) } }
            // PIN 门禁不能用 DEVICE_CREDENTIAL（会绕过 PIN 概念），必须显式「取消」按钮。
            .setNegativeButtonText("取消")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .build()
        prompt.authenticate(info)
    }
}
