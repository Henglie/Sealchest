package com.henglie.sealchest.saf

import android.content.Context
import android.provider.DocumentsContract

/**
 * SAF roots 变更通知。
 *
 * 为什么需要：解锁 / 上锁后，[SealchestDocumentsProvider.queryRoots] 的返回值变了
 * （从「无根」变「一个根」或反之），但系统 DocumentsUI / 第三方文件管理器不会主动
 * 重查——它们缓存着上次结果。尤其老版本（Android 7/9 自带文件管理器、雷电模拟器
 * 那种）更不刷新，导致解锁后在系统文件界面里根本看不见容器入口。
 *
 * 解法：解锁 / 上锁后对 roots URI 发一次 [android.content.ContentResolver.notifyChange]，
 * 主动通知系统重查。这能改善新版系统的表现；但**老版文件管理器可能仍不认第三方
 * SAF Provider**——那是它们的短板，不是本应用能修的。真正不受此限的是内置浏览器
 * （见 BrowserScreen），任何系统上都能用。
 */
object SafNotify {

    /** authority = applicationId + ".documents"，与 Manifest 的 ${applicationId} 占位一致。 */
    private fun authority(context: Context): String = context.packageName + ".documents"

    /** 通知系统「本应用的 SAF 根集合变了」，触发 DocumentsUI 重查 queryRoots。 */
    fun rootsChanged(context: Context) {
        val uri = DocumentsContract.buildRootsUri(authority(context))
        runCatching { context.contentResolver.notifyChange(uri, null) }
    }
}
