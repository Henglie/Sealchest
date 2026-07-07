package com.henglie.sealchest.core

import android.content.Context
import android.content.SharedPreferences

/**
 * 应用设置持久化（SharedPreferences）。仅存非敏感行为偏好，绝不存密码 / 密钥。
 *
 * 自动锁定：容器解锁后，超时 / 切后台 / 息屏可自动上锁（销毁内存密钥），
 * 防手机遗失或离开时容器长期敞开。默认开启超时 + 切后台锁，安全优先。
 */
object Settings {
    private const val PREFS = "sealchest_settings"
    private const val KEY_ENABLED = "auto_lock_enabled"
    private const val KEY_TIMEOUT = "auto_lock_timeout_ms"
    private const val KEY_LOCK_BG = "lock_on_background"
    private const val KEY_LOCK_SCREEN = "lock_on_screen_off"

    /** 超时档位（毫秒）。0 = 关闭超时（仅靠切后台/息屏）。 */
    val TIMEOUT_OPTIONS: List<Pair<Long, String>> = listOf(
        0L to "关闭",
        60_000L to "1 分钟",
        180_000L to "3 分钟",
        300_000L to "5 分钟",
        600_000L to "10 分钟",
        1_800_000L to "30 分钟",
    )

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun autoLockEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ENABLED, true)
    fun setAutoLockEnabled(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_ENABLED, v).apply()

    fun autoLockTimeoutMs(context: Context): Long =
        prefs(context).getLong(KEY_TIMEOUT, 180_000L)
    fun setAutoLockTimeoutMs(context: Context, v: Long) =
        prefs(context).edit().putLong(KEY_TIMEOUT, v).apply()

    fun lockOnBackground(context: Context): Boolean =
        prefs(context).getBoolean(KEY_LOCK_BG, true)
    fun setLockOnBackground(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_LOCK_BG, v).apply()

    fun lockOnScreenOff(context: Context): Boolean =
        prefs(context).getBoolean(KEY_LOCK_SCREEN, false)
    fun setLockOnScreenOff(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_LOCK_SCREEN, v).apply()
}
