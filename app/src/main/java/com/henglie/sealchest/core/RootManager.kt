package com.henglie.sealchest.core

import java.io.File

/**
 * root 检测 + 授权门面（路线图 F1）。所有 root 级增强能力（F 阶段）都挂在本门后。
 *
 * 设计红线（路线图「能力分层」定）：
 *  - **纯增量**：检测无 root / 用户拒绝时，仅隐藏或禁用这些入口，第一层（纯用户态主线）零影响。
 *  - **绝不主动请求**：[detect] 只做被动探测（查 su 文件 / Magisk 痕迹），**不执行 su、不弹授权框**。
 *    真正请求 root 只在用户明确点了某个 root 增强功能、且看过风险提示后，才经 [requestRoot] 触发。
 *  - **绝不让主线依赖 root**：本类的任何返回都不影响文件容器解锁/读写/创建等主线能力。
 *
 * 探测与请求分离：
 *  - [detect]：被动、无副作用、可随时调（如渲染设置页判断是否显示 root 入口）。
 *  - [requestRoot]：主动执行一次 `su -c id`，会触发 Magisk/SuperSU 授权弹框。仅在用户
 *    知情同意后调用。结果缓存，供后续 F2/F3 能力复用。
 *
 * 线程：[requestRoot] 会阻塞（起子进程等 IO），调用方须放后台线程；[detect] 轻量可主线程。
 */
object RootManager {

    /** root 授权状态。 */
    enum class RootState {
        /** 尚未探测。 */
        UNKNOWN,

        /** 探测到设备存在 root（有 su 二进制 / Magisk），但尚未请求授权。 */
        AVAILABLE,

        /** 已请求且被授予（`su -c id` 成功返回 uid=0）。 */
        GRANTED,

        /** 已请求但被拒绝 / 超时。 */
        DENIED,

        /** 设备未 root（无任何 su 痕迹）。 */
        UNAVAILABLE,
    }

    @Volatile
    private var cachedState: RootState = RootState.UNKNOWN

    /** su 二进制常见路径（被动查文件是否存在，不执行）。 */
    private val SU_PATHS = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sbin/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
    )

    /** Magisk 常见痕迹路径。 */
    private val MAGISK_PATHS = arrayOf(
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/modules",
    )

    /**
     * 被动探测设备是否 root（**不执行 su、不弹框**）。
     * 已 [GRANTED]/[DENIED] 则保持不覆盖（那是请求后的确定态）；否则按文件痕迹判 AVAILABLE/UNAVAILABLE。
     * 返回当前 [RootState]。
     */
    fun detect(): RootState {
        val current = cachedState
        if (current == RootState.GRANTED || current == RootState.DENIED) return current
        val present = SU_PATHS.any { safeExists(it) } || MAGISK_PATHS.any { safeExists(it) }
        val next = if (present) RootState.AVAILABLE else RootState.UNAVAILABLE
        cachedState = next
        return next
    }

    /** 当前缓存的状态（不触发探测）。渲染 UI 时用，避免重复 IO。 */
    fun state(): RootState = cachedState

    /**
     * 是否「可能」具备 root 能力（探测到或已授予）。用于决定 root 增强入口是否**显示**。
     * 注意：显示 ≠ 已授权，真正用到 root 的操作仍须 [requestRoot] 成功。
     */
    fun isRootPossible(): Boolean {
        val s = if (cachedState == RootState.UNKNOWN) detect() else cachedState
        return s == RootState.AVAILABLE || s == RootState.GRANTED
    }

    /** 是否已确切授予 root（可直接执行特权操作）。 */
    fun isGranted(): Boolean = cachedState == RootState.GRANTED

    /**
     * 主动请求 root 授权：执行一次 `su -c id`，触发 Magisk/SuperSU 弹框。
     * **仅在用户知情同意后调用**（点了某 root 增强功能 + 看过风险提示）。会阻塞，放后台线程。
     * 成功（stdout 含 uid=0）置 [GRANTED] 返 true；失败/拒绝/无 su 置 [DENIED]/[UNAVAILABLE] 返 false。
     */
    fun requestRoot(): Boolean {
        if (detect() == RootState.UNAVAILABLE) {
            cachedState = RootState.UNAVAILABLE
            return false
        }
        val ok = runCatching {
            val process = ProcessBuilder("su", "-c", "id")
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor()
            process.exitValue() == 0 && output.contains("uid=0")
        }.getOrDefault(false)
        cachedState = if (ok) RootState.GRANTED else RootState.DENIED
        return ok
    }

    /** 重置授权缓存（如用户在设置里主动「断开 root」或需重新探测）。 */
    fun reset() {
        cachedState = RootState.UNKNOWN
    }

    /** 查文件是否存在，屏蔽 SELinux 拒绝等异常（探测绝不抛）。 */
    private fun safeExists(path: String): Boolean =
        runCatching { File(path).exists() }.getOrDefault(false)
}
