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
        prefs(context).getBoolean(KEY_LOCK_BG, false)
    fun setLockOnBackground(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_LOCK_BG, v).apply()

    fun lockOnScreenOff(context: Context): Boolean =
        prefs(context).getBoolean(KEY_LOCK_SCREEN, false)
    fun setLockOnScreenOff(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_LOCK_SCREEN, v).apply()

    // ---- 生物识别解锁 PIN 门禁开关（X4）。仅在已设 PIN 时有意义。----
    //   行为偏好，非敏感：存普通 SharedPreferences。开启后启动 app 可用指纹/面部
    //   解锁门禁，免输 PIN。Panic PIN 不走生物识别（必须手动输，防误触擦除）。
    private const val KEY_BIOMETRIC_UNLOCK = "biometric_unlock_enabled"
    fun biometricUnlockEnabled(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BIOMETRIC_UNLOCK, false)
    fun setBiometricUnlockEnabled(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_BIOMETRIC_UNLOCK, v).apply()

    // ---- 默认偏好（X13）：默认挂载模式 / 默认 PRF。绝不存密钥。----
    private const val KEY_DEFAULT_MOUNT_WRITABLE = "default_mount_writable"
    private const val KEY_DEFAULT_PRF_INDEX = "default_prf_index"

    /** 默认挂载模式：true=读写，false=只读。解锁时作初始值，用户可逐次覆盖。 */
    fun defaultMountWritable(context: Context): Boolean =
        prefs(context).getBoolean(KEY_DEFAULT_MOUNT_WRITABLE, true)
    fun setDefaultMountWritable(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_DEFAULT_MOUNT_WRITABLE, v).apply()

    /** 默认 PRF 选项索引（对齐 MainActivity.PRF_OPTIONS，0=自动）。 */
    fun defaultPrfIndex(context: Context): Int =
        prefs(context).getInt(KEY_DEFAULT_PRF_INDEX, 0)
    fun setDefaultPrfIndex(context: Context, v: Int) =
        prefs(context).edit().putInt(KEY_DEFAULT_PRF_INDEX, v.coerceIn(0, 5)).apply()

    // ---- NTFS 实验开关（默认关）。开启才允许挂载 NTFS 容器（读写待真机 chkdsk 验收）。----
    //   正常用户零影响：关闭时 NTFS 一律拒绝挂载（宁可打不开，绝不挂垃圾/误写）。
    //   恒烈真机验收专用：先只读验证（挂只读零写风险），读通过再开可写验写。
    private const val KEY_NTFS_EXPERIMENTAL = "ntfs_experimental"
    fun ntfsExperimental(context: Context): Boolean =
        prefs(context).getBoolean(KEY_NTFS_EXPERIMENTAL, false)
    fun setNtfsExperimental(context: Context, v: Boolean) =
        prefs(context).edit().putBoolean(KEY_NTFS_EXPERIMENTAL, v).apply()

    // ---- 语言偏好（16 国语言切换）。空串=跟随系统。----
    private const val KEY_LANG = "language_tag"
    fun languageTag(context: Context): String =
        prefs(context).getString(KEY_LANG, "") ?: ""
    fun setLanguageTag(context: Context, tag: String) =
        prefs(context).edit().putString(KEY_LANG, tag).apply()

    // ---- 主题色（用户可自由调整的强调色，覆盖 MaterialTheme 的 primary）。----
    //   存 ARGB int。默认 0 = 跟随系统（动态取色 Material You，不覆盖 primary）；
    //   非 0 = 用户选的固定预设色（关动态取色，纯色主题）。两者互斥，不叠加。
    private const val KEY_THEME_COLOR = "theme_color"
    /** 主题色 ARGB；返回 0 表示「跟随系统」（用动态取色 / 兜底配色，不覆盖 primary）。 */
    fun themeColor(context: Context): Int =
        prefs(context).getInt(KEY_THEME_COLOR, 0)
    fun setThemeColor(context: Context, argb: Int) =
        prefs(context).edit().putInt(KEY_THEME_COLOR, argb).apply()

    // ---- 夜间模式（0=跟随系统 1=浅色 2=深色）。仅行为偏好，非敏感。----
    private const val KEY_THEME_MODE = "theme_mode"
    /** 0=跟随系统 1=浅色 2=深色。 */
    fun themeMode(context: Context): Int =
        prefs(context).getInt(KEY_THEME_MODE, 0)
    fun setThemeMode(context: Context, mode: Int) =
        prefs(context).edit().putInt(KEY_THEME_MODE, mode).apply()

    // ---- 收藏容器（多容器快速切换，E 阶段）。仅存 URI+名字+时间，绝不存密码/密钥。----
    private const val KEY_FAVORITES = "favorite_containers"

    /** 一个收藏容器：持久化 URI 串 + 显示名 + 上次使用毫秒。 */
    data class Favorite(val uri: String, val name: String, val lastUsed: Long, val order: Int = 0)

    /** 读收藏列表，按上次使用倒序（最近在前）。 */
    fun favorites(context: Context): List<Favorite> {
        val raw = prefs(context).getString(KEY_FAVORITES, null) ?: return emptyList()
        return try {
            val arr = org.json.JSONArray(raw)
            val out = ArrayList<Favorite>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                out.add(Favorite(o.getString("uri"), o.optString("name", ""), o.optLong("lastUsed", 0L), o.optInt("order", 0)))
            }
            out.sortedWith(compareBy<Favorite> { it.order }.thenByDescending { it.lastUsed })
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

    /** 清空所有收藏（Panic 紧急擦除用）。 */
    fun clearFavorites(context: Context) {
        writeFavorites(context, emptyList())
    }

    /** 重命名收藏项（改 name，不动 uri/order/lastUsed）。 */
    fun renameFavorite(context: Context, uri: String, newName: String) {
        val cur = favorites(context)
        writeFavorites(context, cur.map { if (it.uri == uri) it.copy(name = newName) else it })
    }

    /**
     * 调整收藏项顺序（X9）：把 [uri] 移到位置 [newOrder]，其余项顺序号顺延。
     * order 越小越靠前；同 order 按 lastUsed 倒序。置顶 = newOrder=0。
     */
    fun reorderFavorite(context: Context, uri: String, newOrder: Int) {
        val cur = favorites(context)
        val target = cur.firstOrNull { it.uri == uri } ?: return
        val others = cur.filter { it.uri != uri }
        // 重新分配连续 order：目标插入 newOrder 位置，其余顺延。
        val before = others.filter { it.order < newOrder || (it.order == newOrder && false) }
        val after = others.filter { it.order >= newOrder }
        val merged = before + target.copy(order = newOrder) + after.mapIndexed { i, f -> f.copy(order = newOrder + 1 + i) }
        writeFavorites(context, merged)
    }

    private fun writeFavorites(context: Context, list: List<Favorite>) {
        val arr = org.json.JSONArray()
        for (f in list) {
            val o = org.json.JSONObject()
            o.put("uri", f.uri); o.put("name", f.name); o.put("lastUsed", f.lastUsed); o.put("order", f.order)
            arr.put(o)
        }
        prefs(context).edit().putString(KEY_FAVORITES, arr.toString()).apply()
    }

}
