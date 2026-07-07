package com.henglie.sealchest

import android.app.Application
import com.henglie.sealchest.core.AutoLock

/**
 * Application 入口：进程创建时装好自动锁定（前后台观察 + 息屏广播）。
 * 见 [AutoLock]。Manifest 的 application android:name 指向本类。
 */
class SealchestApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AutoLock.init(this)
    }
}
