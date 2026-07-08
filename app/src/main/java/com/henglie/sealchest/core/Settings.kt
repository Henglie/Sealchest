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

    // ---- 收藏容器（多容器快速切换，E 阶段）。仅存 URI+名字+时间，绝不存密码/密钥。----
    private const val KEY_FAVORITES = "favorite_containers"

    /** 一个收藏容器：持久化 URI 串 + 显示名 + 上次使用毫秒。 */
    data class Favorite(val uri: String, val name: String, val lastUsed: Long)

    /** 读收藏列表，按上次使用倒序（最近在前）。 */
    fun favorites(context: Context): List<Favorite> {
        val raw = prefs(context).getString(KEY_FAVORITES, null) ?: return emptyList()
        return try {
            val arr = org.json.JSONArray(raw)
            val out = ArrayList<Favorite>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                out.add(Favorite(o.getString("uri"), o.optString("name", ""), o.optLong("lastUsed", 0L)))
            }
            out.sortedByDescending { it.lastUsed }
        } catch (e: Exception) { emptyList() }
    }

    /** 加入或更新收藏（同 URI 去重，刷新名字与 lastUsed）。 */
    fun addFavorite(context: Context, uri: String, name: String) {
        val cur = favorites(context).filter { it.uri != uri }
        writeFavorites(context, cur + Favorite(uri, name, System.currentTimeMillis()))
    }

    /** 移除收藏。 */
    fun removeFavorite(context: Context, uri: String) {
        writeFavorites(context, favorites(context).filter { it.uri != uri })
    }

    private fun writeFavorites(context: Context, list: List<Favorite>) {
        val arr = org.json.JSONArray()
        for (f in list) {
            val o = org.json.JSONObject()
            o.put("uri", f.uri); o.put("name", f.name); o.put("lastUsed", f.lastUsed)
            arr.put(o)
        }
        prefs(context).edit().putString(KEY_FAVORITES, arr.toString()).apply()
    }

}
