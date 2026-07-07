package com.henglie.sealchest.core

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.henglie.sealchest.fs.MountManager

/**
 * 自动锁定：容器解锁后，无操作超时 / 切后台 / 息屏时自动 [MountManager.lock]
 * 销毁内存密钥。防手机遗失或人离开时容器长期敞开。行为由 [Settings] 配置。
 *
 * 三条触发线：
 *  1. 超时——Handler 延时任务，[touch] 重置计时（UI 有交互就调）。到点且仍挂载则锁。
 *  2. 切后台——[ProcessLifecycleOwner] onStop（整个 app 进后台）时按配置立即锁。
 *  3. 息屏——ACTION_SCREEN_OFF 广播，按配置立即锁。
 *
 * 只在「已挂载」时有意义；未挂载时计时器空转无副作用。[init] 在 Application 调一次。
 */
object AutoLock {
    private val handler = Handler(Looper.getMainLooper())
    private var appContext: Context? = null

    /** 超时到点执行体：仍挂载才锁。 */
    private val timeoutRunnable = Runnable {
        val ctx = appContext ?: return@Runnable
        if (Settings.autoLockEnabled(ctx) && MountManager.isMounted) {
            MountManager.lock(ctx)
        }
    }

    /** 息屏广播接收：按配置立即锁。 */
    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != Intent.ACTION_SCREEN_OFF) return
            val ctx = appContext ?: return
            if (Settings.autoLockEnabled(ctx) && Settings.lockOnScreenOff(ctx) && MountManager.isMounted) {
                MountManager.lock(ctx)
            }
        }
    }

    /** 前后台观察：整 app 进后台（onStop）时按配置锁。 */
    private val lifecycleObserver = object : DefaultLifecycleObserver {
        override fun onStop(owner: LifecycleOwner) {
            val ctx = appContext ?: return
            if (Settings.autoLockEnabled(ctx) && Settings.lockOnBackground(ctx) && MountManager.isMounted) {
                MountManager.lock(ctx)
            }
        }
    }

    /** Application.onCreate 调一次：装前后台观察 + 注册息屏广播。 */
    fun init(context: Context) {
        appContext = context.applicationContext
        ProcessLifecycleOwner.get().lifecycle.addObserver(lifecycleObserver)
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        context.applicationContext.registerReceiver(screenOffReceiver, filter)
    }

    /**
     * 用户有交互 / 刚解锁时调：重置超时计时。未挂载或超时关闭则只清计时器。
     * 在 UI 顶层（onUserInteraction / 挂载成功）调。
     */
    fun touch() {
        val ctx = appContext ?: return
        handler.removeCallbacks(timeoutRunnable)
        if (!Settings.autoLockEnabled(ctx)) return
        val timeout = Settings.autoLockTimeoutMs(ctx)
        if (timeout > 0 && MountManager.isMounted) {
            handler.postDelayed(timeoutRunnable, timeout)
        }
    }

    /** 上锁后 / 停止时清计时器，避免空跑。 */
    fun cancel() {
        handler.removeCallbacks(timeoutRunnable)
    }
}
