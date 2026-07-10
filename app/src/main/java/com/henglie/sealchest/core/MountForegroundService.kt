package com.henglie.sealchest.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.henglie.sealchest.MainActivity
import com.henglie.sealchest.fs.MountManager

/**
 * 挂载保活前台服务（路线图 F4）。
 *
 * 容器解锁后启动此服务，常驻通知栏防系统杀后台 → 密钥丢失。
 * onTaskRemoved（用户划掉 app）时紧急上锁（尽力）。
 *
 * 诚实边界：保活非 100%。现代安卓激进杀后台 ROM 无可靠「进程将死」信号。
 * 必须提醒用户去系统设置放行（电池优化白名单、允许后台运行）。
 */
class MountForegroundService : Service() {

    companion object {
        /** 常驻通知 id。固定值，上锁时用它 cancel。 */
        private const val NOTIF_ID = 1001
        /** 通知渠道 id。用 applicationId 防冲突。 */
        private const val CHANNEL_ID = "sealchest_mount"

        /**
         * 启动前台服务。容器解锁后调。已运行则空转（onStartCommand 重发通知无碍）。
         * 用 ContextCompat.startForegroundService 兼容 Android 8+。
         */
        fun start(context: Context) {
            val ctx = context.applicationContext
            val intent = Intent(ctx, MountForegroundService::class.java)
            androidx.core.content.ContextCompat.startForegroundService(ctx, intent)
        }

        /** 停止前台服务。上锁后调。 */
        fun stop(context: Context) {
            val ctx = context.applicationContext
            ctx.stopService(Intent(ctx, MountForegroundService::class.java))
        }
    }

    override fun onCreate() {
        super.onCreate()
        // Android 8+ 必须先建渠道才能发通知。IMPORTANCE_LOW 不响铃，仅常驻通知栏。
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "挂载保活",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "容器挂载期间常驻通知，防止系统杀后台导致密钥丢失"
                // 不可删除通知（渠道级），降低用户误删概率
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // START_STICKY：系统在内存紧回收后尽量重建服务，但不重投递 intent。
        // 重建后 intent 为 null，仍走此处重新 startForeground 保住常驻通知。
        startForeground(NOTIF_ID, buildNotification())
        return START_STICKY
    }

    /**
     * 构造常驻通知。小图标用 android.R.drawable.ic_lock_lock（系统自带，不依赖资源）。
     * FLAG_ONGOING_EVENT 使其不可划除。点击跳 MainActivity 让用户回 app。
     */
    private fun buildNotification(): Notification {
        // 点击通知跳 MainActivity（回 app 主界面）
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        // IMMUTABLE 是 Android 12+ 强制要求；旧机型同样兼容。
        val pi = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("匿匣 · 容器已挂载")
            .setContentText("点击返回 app")
            .setContentIntent(pi)
            // 常驻通知：不可消除、不自动消失
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    /**
     * 用户从最近任务划掉 app 时回调。此时 app 进程可能立刻被杀，[MountManager.lock]
     * 只能尽力：若进程被杀前 lock 跑完则密钥销毁成功，否则来不及（诚实边界）。
     * 锁完 stopSelf 收尾，避免空跑服务。
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        runCatching { MountManager.lock(applicationContext) }
        stopSelf()
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        // 收尾：取消常驻通知，防上锁后通知残留。
        (getSystemService(NotificationManager::class.java))?.cancel(NOTIF_ID)
        super.onDestroy()
    }

    /**
     * 系统内存紧张时回调。TRIM_MEMORY_COMPLETE（内存极紧、即将回收进程）时紧急上锁。
     * 与 onTaskRemoved 同层「尽力」——系统可能直接杀进程来不及跑完 lock。
     */
    override fun onTrimMemory(level: Int) {
        if (level >= TRIM_MEMORY_COMPLETE) {
            runCatching { MountManager.lock(applicationContext) }
            stopSelf()
        }
        super.onTrimMemory(level)
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
