package com.henglie.sealchest.create

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.shape.RoundedCornerShape
import com.henglie.sealchest.R
import com.henglie.sealchest.crypto.NativeBridge

/**
 * 创建新 VeraCrypt 容器的参数（向导 UI 采集，交主开发接线到 native 创建逻辑）。
 *
 * - [algorithm] 加密算法 ID：AES=1, SERPENT=2, TWOFISH=3, CAMELLIA=4, KUZNYECHIK=5。
 *   第一版只做单算法，级联（AES-Twofish 等）留后续。
 * - [prf] PRF/哈希 ID：SHA512=1, WHIRLPOOL=2, SHA256=3, BLAKE2S=4, STREEBOG=5，默认 SHA512=1。
 * - [pim] 个人迭代倍数，0 = 默认迭代。
 * - [sizeBytes] 容器数据区大小（字节）。UI 按 MB 输入，内部 ×1024×1024。
 * - [password] UTF-8 编码的密码字节。用后应由调用方 fill(0) 抹除。
 */
data class CreateParams(
    val algorithm: Int,
    val prf: Int,
    val pim: Int,
    val sizeBytes: Long,
    val password: ByteArray,
) {
    // ByteArray 字段需自定义 equals/hashCode，否则按引用比较（IDE 会警告）。
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CreateParams) return false
        return algorithm == other.algorithm &&
            prf == other.prf &&
            pim == other.pim &&
            sizeBytes == other.sizeBytes &&
            password.contentEquals(other.password)
    }

    override fun hashCode(): Int {
        var result = algorithm
        result = 31 * result + prf
        result = 31 * result + pim
        result = 31 * result + sizeBytes.hashCode()
        result = 31 * result + password.contentHashCode()
        return result
    }
}

/** 加密算法选项：显示名 string res id + 传给 native 的算法 ID。第一版单算法 5 选 1。 */
private val ALGORITHM_OPTIONS = listOf(
    R.string.create_algo_aes to 1,
    R.string.create_algo_serpent to 2,
    R.string.create_algo_twofish to 3,
    R.string.create_algo_camellia to 4,
    R.string.create_algo_kuznyechik to 5,
)

/** PRF 选项：显示名 string res id + 传给 native 的 PRF ID。默认 SHA512=1（列表首项）。 */
private val CREATE_PRF_OPTIONS = listOf(
    R.string.prf_sha512 to 1,
    R.string.prf_whirlpool to 2,
    R.string.prf_sha256 to 3,
    R.string.prf_blake2s to 4,
    R.string.prf_streebog to 5,
)

/** 建议的最小容器大小（MB）。VeraCrypt 实际下限约 256KB，但 <1MB 装不下 FAT 元数据+文件，故建议 ≥1MB。 */
private const val MIN_SIZE_MB = 1L

/**
 * 手指涂抹收集熵的目标触点数（对齐桌面 VeraCrypt「晃鼠标收集熵」）。
 * 每个触点带坐标 + 纳秒时间戳，经 [NativeBridge.addEntropy] 混入 native 熵池的 SHA512 搅拌层。
 * 200 个不可预测的物理输入事件，远超一次卷头所需的熵下限，给足冗余。
 */
private const val ENTROPY_TARGET = 200

/** 每积攒这么多触点就 flush 一次进 native 池（避免每点一次 JNI 调用）。 */
private const val ENTROPY_FLUSH_BATCH = 16

/**
 * 创建新 VeraCrypt 容器向导（B2）。独立 @Composable，主开发稍后接线进 MainActivity。
 *
 * [onCancel] 用户放弃创建。
 * [onCreate] 校验通过后回调采集到的 [CreateParams]，实际创建逻辑由调用方接线。
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun CreateVolumeScreen(
    busy: Boolean,
    message: String?,
    onCancel: () -> Unit,
    onCreate: (CreateParams) -> Unit,
) {
    // 选中项以列表下标表示。算法默认 AES（下标 0），PRF 默认 SHA512（下标 0）。
    var algoIndex by remember { mutableStateOf(0) }
    var prfIndex by remember { mutableStateOf(0) }

    var sizeMb by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    // 大小合法性：正整数且 ≥ 最小建议值。空或非法都视作未通过。
    val sizeMbValue = sizeMb.toLongOrNull()
    val sizeValid = sizeMbValue != null && sizeMbValue >= MIN_SIZE_MB

    // 两次密码一致且非空。VeraCrypt 允许空密码（配 keyfile），但本向导第一版不含 keyfile，强制非空。
    val passwordFilled = password.isNotEmpty()
    val passwordsMatch = password == confirm

    // 熵采集进度：已收集的触点事件数。达到 [ENTROPY_TARGET] 才允许创建（对齐桌面晃鼠标）。
    // 用显式 MutableState（非 by 委托）：suspend 的 awaitPointerEventScope 闭包里
    // 写委托 var 会报 "Val cannot be reassigned"，改 .value 读写则合法。
    val entropyState = remember { mutableStateOf(0) }
    val entropyCollected = entropyState.value
    val entropyReady = entropyCollected >= ENTROPY_TARGET

    val canCreate = sizeValid && passwordFilled && passwordsMatch && entropyReady

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.create_title)) },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.create_cancel),
                        )
                    }
                },
            )
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // ---- 加密算法 ----
            Text(
                stringResource(R.string.create_algorithm),
                style = MaterialTheme.typography.labelLarge,
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                ALGORITHM_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                    FilterChip(
                        selected = algoIndex == i,
                        onClick = { algoIndex = i },
                        label = { Text(stringResource(labelResId)) },
                        modifier = Modifier.widthIn(min = 96.dp),
                    )
                }
            }

            // ---- PRF / 哈希 ----
            Text(
                stringResource(R.string.create_prf),
                style = MaterialTheme.typography.labelLarge,
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                CREATE_PRF_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                    FilterChip(
                        selected = prfIndex == i,
                        onClick = { prfIndex = i },
                        label = { Text(stringResource(labelResId)) },
                        modifier = Modifier.widthIn(min = 96.dp),
                    )
                }
            }

            // ---- 大小（MB）----
            OutlinedTextField(
                value = sizeMb,
                onValueChange = { sizeMb = it.filter(Char::isDigit) },
                label = { Text(stringResource(R.string.create_size_mb)) },
                singleLine = true,
                isError = sizeMb.isNotEmpty() && !sizeValid,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                stringResource(R.string.create_size_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ---- 密码 + 确认 ----
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(stringResource(R.string.create_password)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text(stringResource(R.string.create_password_confirm)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                // 两次都填了才提示不一致，避免用户还在输入就报红。
                isError = confirm.isNotEmpty() && !passwordsMatch,
                modifier = Modifier.fillMaxWidth(),
            )
            if (confirm.isNotEmpty() && !passwordsMatch) {
                Text(
                    stringResource(R.string.create_password_mismatch),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            // ---- PIM（可选）----
            OutlinedTextField(
                value = pim,
                onValueChange = { pim = it.filter(Char::isDigit) },
                label = { Text(stringResource(R.string.create_pim)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                stringResource(R.string.create_pim_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ---- 熵采集：手指在区域内涂抹，采触点坐标+纳秒时间戳喂 native 熵池 ----
            // 对齐桌面 VeraCrypt「晃鼠标收集熵」：用户不可预测的物理输入是随机主密钥的
            // 额外熵源（叠加 SecureRandom）。攒够 ENTROPY_TARGET 个触点才放行创建。
            Text(
                stringResource(R.string.create_entropy_title),
                style = MaterialTheme.typography.labelLarge,
            )
            Text(
                stringResource(R.string.create_entropy_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(140.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(
                        if (entropyReady) MaterialTheme.colorScheme.secondaryContainer
                        else MaterialTheme.colorScheme.surfaceVariant
                    )
                    .pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                val event = awaitPointerEvent()
                                // 每个触点：x/y（Float 位）+ System.nanoTime 低位，凑 12 字节喂熵池。
                                val buf = ByteArray(12)
                                var idx = 0
                                for (ptr in event.changes) {
                                    if (idx > 0) break // 每事件取一个主触点即可，多指下批再采
                                    val xb = ptr.position.x.toRawBits()
                                    val yb = ptr.position.y.toRawBits()
                                    val t = System.nanoTime()
                                    buf[0] = (xb ushr 24).toByte(); buf[1] = (xb ushr 16).toByte()
                                    buf[2] = (xb ushr 8).toByte();  buf[3] = xb.toByte()
                                    buf[4] = (yb ushr 24).toByte(); buf[5] = (yb ushr 16).toByte()
                                    buf[6] = (yb ushr 8).toByte();  buf[7] = yb.toByte()
                                    buf[8] = (t ushr 24).toByte();  buf[9] = (t ushr 16).toByte()
                                    buf[10] = (t ushr 8).toByte();  buf[11] = t.toByte()
                                    com.henglie.sealchest.crypto.NativeBridge.addEntropy(buf)
                                    if (entropyState.value < ENTROPY_TARGET) entropyState.value++
                                    idx++
                                }
                            }
                        }
                    },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (entropyReady) stringResource(R.string.create_entropy_done)
                    else stringResource(
                        R.string.create_entropy_progress,
                        entropyCollected * 100 / ENTROPY_TARGET
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            LinearProgressIndicator(
                progress = { (entropyCollected.toFloat() / ENTROPY_TARGET).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth(),
            )

            // ---- 创建进行中：进度指示 + 提示文字（busy 时显示）----
            if (busy) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    CircularProgressIndicator()
                    Text(
                        stringResource(R.string.create_in_progress),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            // ---- 结果反馈（成功/失败原因），直接显示 message 本身 ----
            if (message != null) {
                Text(
                    message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // ---- 取消 / 创建 ----
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                OutlinedButton(
                    onClick = onCancel,
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(stringResource(R.string.create_cancel))
                }
                Button(
                    onClick = {
                        // 再取一次当前下标对应的 native ID，交回调。密码转 UTF-8 字节。
                        val algoId = ALGORITHM_OPTIONS[algoIndex].second
                        val prfId = CREATE_PRF_OPTIONS[prfIndex].second
                        val pimVal = pim.toIntOrNull() ?: 0
                        val mb = sizeMb.toLongOrNull() ?: return@Button
                        val bytes = mb * 1024L * 1024L
                        onCreate(
                            CreateParams(
                                algorithm = algoId,
                                prf = prfId,
                                pim = pimVal,
                                sizeBytes = bytes,
                                password = password.toByteArray(Charsets.UTF_8),
                            )
                        )
                    },
                    enabled = canCreate && !busy,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(stringResource(R.string.create_submit))
                }
            }
        }
    }
}
