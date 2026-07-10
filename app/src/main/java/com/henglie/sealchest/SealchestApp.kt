package com.henglie.sealchest

import android.app.Application
import com.henglie.sealchest.core.AutoLock
import com.henglie.sealchest.core.MountForegroundService
import com.henglie.sealchest.fs.MountManager

/**
 * Application 入口：进程创建时装好自动锁定（前后台观察 + 息屏广播）。
 * 见 [AutoLock]。Manifest 的 application android:name 指向本类。
 *
 * 挂载状态变化通过 [MountManager.onMountStateChanged] 回调驱动前台服务起停，
 * 实时响应 + 零轮询开销（原方案每秒轮询 isMounted，已废弃）。
 */
class SealchestApp : Application() {

    override fun onCreate() {
        super.onCreate()
        AutoLock.init(this)
        // 注册挂载状态回调：挂载时拉起前台服务保活，上锁时停服务。
        MountManager.onMountStateChanged = { mounted ->
            if (mounted) {
                MountForegroundService.start(this)
            } else {
                MountForegroundService.stop(this)
            }
        }
    }
}
