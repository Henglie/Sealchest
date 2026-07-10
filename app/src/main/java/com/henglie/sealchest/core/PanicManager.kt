package com.henglie.sealchest.core

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Panic PIN 即时擦除管理器。对标 Arcanum 的 panic mode。
 *
 * Panic PIN 是与解锁 PIN 不同的独立 PIN——输入后不进 app，而是立即擦除：
 *  - 已挂载容器立即上锁（销毁内存密钥）[MountManager.lock]
 *  - 收藏列表清空（[Settings.clearFavorites]）
 *  - app 私有目录下的救援文件全部删除（[rescueDir] 递归删）
 *  - PIN 本身清除（连同解锁 PIN）
 *  - cacheDir/exported 明文临时文件清空
 *
 * 设计红线：
 *  - Panic PIN 与解锁 PIN 哈希独立存储，可设可不设。
 *  - 擦除在后台线程跑，UI 先假装进 app（等比响应时间，防暴力探测区分）。
 *  - 擦除尽力——系统可能限制文件删除（如 SAF 授权的容器文件本身删不掉，
 *    但 app 内的数据：收藏/PIN/救援/cache 都能删）。
 *
 * 复用 [PinManager] 的 Argon2id 参数与 EncryptedSharedPreferences 机制。
 */
object PanicManager {
    private const val PREFS_NAME = "sealchest_panic"
    private const val KEY_HASH = "panic_hash"
    private const val KEY_SALT = "panic_salt"
    private const val KEY_SET = "panic_set"

    private const val ARGON_ITERATIONS = 2
    private const val ARGON_MEMORY_KB = 65536 // 64 MB
    private const val ARGON_PARALLELISM = 1
    private const val ARGON_HASH_LEN = 32
    private const val SALT_LEN = 16

    private fun prefs(context: Context) = runCatching {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }.getOrNull()

    /** Panic PIN 是否已设置。 */
    fun isPanicPinSet(context: Context): Boolean =
        prefs(context)?.getBoolean(KEY_SET, false) ?: false

    /** 设置 Panic PIN。 */
    fun setPanicPin(context: Context, pin: String) {
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val hash = argon2id(pin.toByteArray(Charsets.UTF_8), salt)
        prefs(context)?.edit()
            ?.putString(KEY_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
            ?.putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            ?.putBoolean(KEY_SET, true)
            ?.apply()
    }

    /** 验证 Panic PIN。 */
    fun verifyPanicPin(context: Context, pin: String): Boolean {
        val p = prefs(context) ?: return false
        val hashB64 = p.getString(KEY_HASH, null) ?: return false
        val saltB64 = p.getString(KEY_SALT, null) ?: return false
        val storedHash = runCatching { Base64.decode(hashB64, Base64.DEFAULT) }.getOrNull() ?: return false
        val salt = runCatching { Base64.decode(saltB64, Base64.DEFAULT) }.getOrNull() ?: return false
        val inputHash = argon2id(pin.toByteArray(Charsets.UTF_8), salt)
        return MessageDigest.isEqual(inputHash, storedHash)
    }

    /** 清除 Panic PIN。 */
    fun clearPanicPin(context: Context) {
        prefs(context)?.edit()
            ?.remove(KEY_HASH)?.remove(KEY_SALT)?.remove(KEY_SET)?.apply()
    }

    /**
     * 执行紧急擦除。尽力——系统可能限制部分删除，能删的都删。
     * 在后台线程调。
     *
     * @return 擦除报告（删了什么）。
     */
    fun executePanicWipe(context: Context): String {
        val sb = StringBuilder()
        val ctx = context.applicationContext

        // 1. 立即上锁已挂载容器（销毁内存密钥）。
        runCatching {
            com.henglie.sealchest.fs.MountManager.lock(ctx)
            sb.append("已上锁容器；")
        }

        // 2. 清空收藏列表。
        runCatching {
            Settings.clearFavorites(ctx)
            sb.append("已清收藏；")
        }

        // 3. 删 app 私有目录下的救援文件（rescue 子目录递归删）。
        runCatching {
            val rescueDir = File(ctx.filesDir, "rescue")
            if (rescueDir.exists()) {
                rescueDir.deleteRecursively()
                sb.append("已删救援文件；")
            }
        }

        // 4. 清 cacheDir 下明文临时文件（exported / encrypted_media_tmp 等）。
        runCatching {
            ctx.cacheDir.listFiles()?.forEach { sub ->
                if (sub.isDirectory) sub.deleteRecursively() else sub.delete()
            }
            sb.append("已清缓存；")
        }

        // 5. 清 PIN 与 Panic PIN（让攻击者无法再探测）。
        runCatching {
            PinManager.clearPin(ctx)
            clearPanicPin(ctx)
            sb.append("已清 PIN；")
        }

        return if (sb.isEmpty()) "无数据可擦除" else sb.toString()
    }

    private fun argon2id(pin: ByteArray, salt: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withMemoryAsKB(ARGON_MEMORY_KB)
            .withIterations(ARGON_ITERATIONS)
            .withParallelism(ARGON_PARALLELISM)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val output = ByteArray(ARGON_HASH_LEN)
        gen.generateBytes(pin, output, 0, ARGON_HASH_LEN)
        return output
    }
}
