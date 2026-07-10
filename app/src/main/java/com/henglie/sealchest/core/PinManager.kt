package com.henglie.sealchest.core

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * PIN 锁管理器。Argon2id 派生 PIN 哈希存 EncryptedSharedPreferences。
 *
 * 对标 Arcanum：Argon2id(t=2, m=64MB, p=1)，PIN 不明文存储，只存哈希+盐。
 *
 * PIN 与容器密码独立——PIN 是 app 启动门禁，不参与容器解锁。
 * 容器解锁仍用各自的密码/keyfile。
 *
 * EncryptedSharedPreferences 用 AndroidKeyStore 托管的主密钥（AES256_GCM）加密整份
 * prefs 文件，密钥不入盘、不进代码。即使 root 抓盘也拿不到 PIN 哈希明文。
 */
object PinManager {
    private const val PREFS_NAME = "sealchest_pin"
    private const val KEY_HASH = "pin_hash"
    private const val KEY_SALT = "pin_salt"
    private const val KEY_SET = "pin_set"

    // Argon2id 参数（对标 Arcanum）
    private const val ARGON_ITERATIONS = 2
    private const val ARGON_MEMORY_KB = 65536 // 64 MB
    private const val ARGON_PARALLELISM = 1
    private const val ARGON_HASH_LEN = 32
    private const val SALT_LEN = 16

    /**
     * 建 EncryptedSharedPreferences 实例（AndroidKeyStore 自动管理主密钥）。
     * 失败返回 null（如老机型 keystore 异常）——此时 PIN 门禁优雅降级为「未设置」，
     * 不阻塞 app 进入，用户可重试设置。
     */
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

    /** PIN 是否已设置。 */
    fun isPinSet(context: Context): Boolean =
        prefs(context)?.getBoolean(KEY_SET, false) ?: false

    /** 设置 PIN。生成随机盐 → Argon2id 派生 → 存哈希+盐。覆盖旧 PIN。 */
    fun setPin(context: Context, pin: String) {
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val hash = argon2id(pin.toByteArray(Charsets.UTF_8), salt)
        prefs(context)?.edit()
            ?.putString(KEY_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
            ?.putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
            ?.putBoolean(KEY_SET, true)
            ?.apply()
    }

    /** 验证 PIN。用存的盐 Argon2id 派生，与存哈希常量时间比对（[MessageDigest.isEqual]）。 */
    fun verifyPin(context: Context, pin: String): Boolean {
        val p = prefs(context) ?: return false
        val hashB64 = p.getString(KEY_HASH, null) ?: return false
        val saltB64 = p.getString(KEY_SALT, null) ?: return false
        val storedHash = runCatching { Base64.decode(hashB64, Base64.DEFAULT) }.getOrNull() ?: return false
        val salt = runCatching { Base64.decode(saltB64, Base64.DEFAULT) }.getOrNull() ?: return false
        val inputHash = argon2id(pin.toByteArray(Charsets.UTF_8), salt)
        return MessageDigest.isEqual(inputHash, storedHash)
    }

    /** 清除 PIN。 */
    fun clearPin(context: Context) {
        prefs(context)?.edit()
            ?.remove(KEY_HASH)
            ?.remove(KEY_SALT)
            ?.remove(KEY_SET)
            ?.apply()
    }

    /** Argon2id 派生。用 [Argon2BytesGenerator] + ARGON2_id 参数。 */
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
