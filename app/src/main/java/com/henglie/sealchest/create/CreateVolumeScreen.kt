package com.henglie.sealchest.create

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.material3.Checkbox
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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import com.henglie.sealchest.R
import com.henglie.sealchest.crypto.NativeBridge
import kotlinx.coroutines.delay

/**
 * 创建新 VeraCrypt 容器的参数（向导 UI 采集，交主创建逻辑接线）。
 *
 * - [algorithm] 加密算法 ID：AES=1, SERPENT=2, TWOFISH=3, CAMELLIA=4, KUZNYECHIK=5。
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
    /** 文件系统：0=FAT（可创建），1=exFAT（后端待接），2=NTFS（后端待接）。 */
    val fsType: Int = 0,
    /** 簇大小（字节）。0=自动（沿用 Formatter 阶梯），否则须为 512 的幂次倍数。 */
    val clusterSize: Int = 0,
    /** 动态卷（稀疏）：UI 已备，后端暂当普通卷处理（见 X2 回执）。 */
    val dynamic: Boolean = false,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CreateParams) return false
        return algorithm == other.algorithm &&
            prf == other.prf &&
            pim == other.pim &&
            sizeBytes == other.sizeBytes &&
            password.contentEquals(other.password) &&
            fsType == other.fsType &&
            clusterSize == other.clusterSize &&
            dynamic == other.dynamic
    }

    override fun hashCode(): Int {
        var result = algorithm
        result = 31 * result + prf
        result = 31 * result + pim
        result = 31 * result + sizeBytes.hashCode()
        result = 31 * result + password.contentHashCode()
        result = 31 * result + fsType
        result = 31 * result + clusterSize
        result = 31 * result + dynamic.hashCode()
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

/** 文件系统选项：显示名 string res id + ID。0=FAT（可创建），1=exFAT / 2=NTFS 后端未就绪灰显。 */
private val FS_OPTIONS = listOf(
    R.string.create_fs_fat to 0,
    R.string.create_fs_exfat to 1,
    R.string.create_fs_ntfs to 2,
)

/** 簇大小选项（字节）。0=自动（沿用 Formatter 阶梯），其余为显式字节值。 */
private val CLUSTER_OPTIONS = listOf(
    R.string.create_cluster_default to 0,
    R.string.create_cluster_512 to 512,
    R.string.create_cluster_1024 to 1024,
    R.string.create_cluster_2048 to 2048,
    R.string.create_cluster_4096 to 4096,
    R.string.create_cluster_8192 to 8192,
    R.string.create_cluster_16384 to 16384,
    R.string.create_cluster_32768 to 32768,
)

/** 建议的最小容器大小（MB）。<1MB 装不下 FAT 元数据+文件，故建议 ≥1MB。 */
private const val MIN_SIZE_MB = 1L

/**
 * 手指涂抹收集熵的目标触点数（对齐桌面 VeraCrypt「晃鼠标收集熵」）。
 * 每触点带坐标 + 纳秒时间戳，经 [NativeBridge.addEntropy] 混入 native 熵池的 SHA512 搅拌层。
 * 桌面版要求用户涂抹到自己满意为止，这里给一个足够长的目标（约 5-10 秒连续涂抹），
 * 远超一次卷头所需的熵下限，给足冗余，也让仪式感更接近桌面版。
 */
private const val ENTROPY_TARGET = 600

/**
 * 创建新 VeraCrypt 容器向导（B2）。两阶段：
 *   阶段 0 表单页：算法 / PRF / 大小 / 密码 / PIM，填完点「下一步」。
 *   阶段 1 全屏熵页：满屏涂抹 + 晃动手机（加速度传感器）双路收集熵，实时显示 native
 *     随机池的字节跳动（对齐桌面 VeraCrypt 的 Random Pool 显示），攒够才放行创建。
 *
 * [onCreate] 契约不变——阶段 1 收够熵后回调采集到的 [CreateParams]，MainActivity 无需改动。
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun CreateVolumeScreen(
    busy: Boolean,
    message: String?,
    onCancel: () -> Unit,
    onCreate: (CreateParams) -> Unit,
) {
    // 两阶段：0 = 表单，1 = 全屏熵页。busy（创建进行中）时停在熵页看进度。
    var phase by remember { mutableStateOf(0) }

    var algoIndex by remember { mutableStateOf(0) }
    var prfIndex by remember { mutableStateOf(0) }
    var fsIndex by remember { mutableStateOf(0) }
    var clusterIndex by remember { mutableStateOf(0) }
    var dynamic by remember { mutableStateOf(false) }
    var sizeMb by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    val sizeMbValue = sizeMb.toLongOrNull()
    val sizeValid = sizeMbValue != null && sizeMbValue >= MIN_SIZE_MB
    val passwordFilled = password.isNotEmpty()
    val passwordsMatch = password == confirm
    val formValid = sizeValid && passwordFilled && passwordsMatch

    if (phase == 0) {
        CreateFormPage(
            algoIndex = algoIndex,
            onAlgoChange = { algoIndex = it },
            prfIndex = prfIndex,
            onPrfChange = { prfIndex = it },
            sizeMb = sizeMb,
            onSizeChange = { sizeMb = it.filter(Char::isDigit) },
            sizeValid = sizeValid,
            password = password,
            onPasswordChange = { password = it },
            confirm = confirm,
            onConfirmChange = { confirm = it },
            passwordsMatch = passwordsMatch,
            pim = pim,
            onPimChange = { pim = it.filter(Char::isDigit) },
            fsIndex = fsIndex,
            onFsChange = { fsIndex = it },
            clusterIndex = clusterIndex,
            onClusterChange = { clusterIndex = it },
            dynamic = dynamic,
            onDynamicChange = { dynamic = it },
            formValid = formValid,
            onCancel = onCancel,
            onNext = { phase = 1 },
        )
    } else {
        EntropyPage(
            busy = busy,
            message = message,
            onBack = { if (!busy) phase = 0 },
            onCreate = {
                val algoId = ALGORITHM_OPTIONS[algoIndex].second
                val prfId = CREATE_PRF_OPTIONS[prfIndex].second
                val pimVal = pim.toIntOrNull() ?: 0
                val mb = sizeMb.toLongOrNull() ?: return@EntropyPage
                onCreate(
                    CreateParams(
                        algorithm = algoId,
                        prf = prfId,
                        pim = pimVal,
                        sizeBytes = mb * 1024L * 1024L,
                        password = password.toByteArray(Charsets.UTF_8),
                        fsType = FS_OPTIONS[fsIndex].second,
                        clusterSize = CLUSTER_OPTIONS[clusterIndex].second,
                        dynamic = dynamic,
                    )
                )
            },
        )
    }
}

/** 阶段 0：参数表单页。填完点「下一步」进熵页。 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun CreateFormPage(
    algoIndex: Int,
    onAlgoChange: (Int) -> Unit,
    prfIndex: Int,
    onPrfChange: (Int) -> Unit,
    sizeMb: String,
    onSizeChange: (String) -> Unit,
    sizeValid: Boolean,
    password: String,
    onPasswordChange: (String) -> Unit,
    confirm: String,
    onConfirmChange: (String) -> Unit,
    passwordsMatch: Boolean,
    pim: String,
    onPimChange: (String) -> Unit,
    fsIndex: Int,
    onFsChange: (Int) -> Unit,
    clusterIndex: Int,
    onClusterChange: (Int) -> Unit,
    dynamic: Boolean,
    onDynamicChange: (Boolean) -> Unit,
    formValid: Boolean,
    onCancel: () -> Unit,
    onNext: () -> Unit,
) {
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
            Text(stringResource(R.string.create_algorithm), style = MaterialTheme.typography.labelLarge)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                ALGORITHM_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                    FilterChip(
                        selected = algoIndex == i,
                        onClick = { onAlgoChange(i) },
                        label = { Text(stringResource(labelResId)) },
                        modifier = Modifier.widthIn(min = 96.dp),
                    )
                }
            }

            // ---- PRF / 哈希 ----
            Text(stringResource(R.string.create_prf), style = MaterialTheme.typography.labelLarge)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                CREATE_PRF_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                    FilterChip(
                        selected = prfIndex == i,
                        onClick = { onPrfChange(i) },
                        label = { Text(stringResource(labelResId)) },
                        modifier = Modifier.widthIn(min = 96.dp),
                    )
                }
            }

            // ---- 大小（MB）----
            OutlinedTextField(
                value = sizeMb,
                onValueChange = onSizeChange,
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
                onValueChange = onPasswordChange,
                label = { Text(stringResource(R.string.create_password)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = confirm,
                onValueChange = onConfirmChange,
                label = { Text(stringResource(R.string.create_password_confirm)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
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
                onValueChange = onPimChange,
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

            // ---- 文件系统（X2）：FAT 可选，exFAT / NTFS 后端未就绪灰显 ----
            Text(stringResource(R.string.create_fs_type), style = MaterialTheme.typography.labelLarge)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                FS_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                    FilterChip(
                        selected = fsIndex == i,
                        onClick = { onFsChange(i) },
                        enabled = i == 0, // 仅 FAT 可创建，exFAT / NTFS 后端待接
                        label = {
                            Text(
                                if (i == 0) stringResource(labelResId)
                                else stringResource(labelResId) + " " + stringResource(R.string.create_fs_coming_soon)
                            )
                        },
                        modifier = Modifier.widthIn(min = 96.dp),
                    )
                }
            }

            // ---- 簇大小（X2）：0=自动沿用 Formatter 阶梯，其余为显式字节值 ----
            Text(stringResource(R.string.create_cluster_size), style = MaterialTheme.typography.labelLarge)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                CLUSTER_OPTIONS.forEachIndexed { i, (labelResId, _) ->
                    FilterChip(
                        selected = clusterIndex == i,
                        onClick = { onClusterChange(i) },
                        label = { Text(stringResource(labelResId)) },
                        modifier = Modifier.widthIn(min = 96.dp),
                    )
                }
            }

            // ---- 动态卷（X2）：UI 已备，后端暂当普通卷处理 ----
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Checkbox(
                    checked = dynamic,
                    onCheckedChange = onDynamicChange,
                )
                Column {
                    Text(stringResource(R.string.create_dynamic))
                    Text(
                        stringResource(R.string.create_dynamic_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            // ---- 取消 / 下一步 ----
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.create_cancel))
                }
                Button(
                    onClick = onNext,
                    enabled = formValid,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(stringResource(R.string.create_next))
                }
            }
        }
    }
}

/**
 * 阶段 1：全屏熵收集页。
 *
 * 双路熵源，都喂进同一个 native 搅拌池（[NativeBridge.addEntropy]）：
 *   ① 满屏手指涂抹——触点坐标 + 纳秒时间戳（对齐桌面「晃鼠标」，全屏更容易涂满目标）。
 *   ② 加速度传感器晃动——x/y/z 读数 + 纳秒时间戳。无加速度计的机型静默跳过（不影响创建）。
 *
 * 实时显示 native 随机池快照（[NativeBridge.randomPoolSnapshot]）的 hex 网格，每 ~80ms 刷新，
 * 让用户直观看到「加密流」在跳动（对齐桌面 VeraCrypt 的 Random Pool 显示）。快照是只读旁观，
 * 不消耗熵、不影响真实取数。
 *
 * 进度以涂抹触点计（[ENTROPY_TARGET]）；传感器熵是持续增强，不单独计入放行门槛，但同样入池。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EntropyPage(
    busy: Boolean,
    message: String?,
    onBack: () -> Unit,
    onCreate: () -> Unit,
) {
    val context = LocalContext.current

    // 涂抹触点计数（放行门槛）。显式 MutableState：suspend 闭包里写委托 var 会报错。
    val swipeState = remember { mutableStateOf(0) }
    val swipeCount = swipeState.value
    val entropyReady = swipeCount >= ENTROPY_TARGET

    // 随机池快照（hex 文本），每 ~80ms 刷新一次，呈现跳动的「加密流」。
    var poolHex by remember { mutableStateOf("") }
    // 是否检测到加速度计（无则界面提示「此机无传感器」，但不影响创建）。
    var hasSensor by remember { mutableStateOf(false) }

    // ---- 加速度传感器：注册监听，每次读数喂熵池 ----
    DisposableEffect(Unit) {
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        val accel = sm?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        hasSensor = accel != null
        val listener = object : SensorEventListener {
            override fun onSensorChanged(e: SensorEvent) {
                // x/y/z 三个 float（各 4B）+ 纳秒时间戳低 4B = 16B 喂池。传感器噪声本身
                // 不可预测，晃动叠加更强；纯静置也有底噪，但主熵靠 SecureRandom 兜底。
                val xb = e.values.getOrElse(0) { 0f }.toRawBits()
                val yb = e.values.getOrElse(1) { 0f }.toRawBits()
                val zb = e.values.getOrElse(2) { 0f }.toRawBits()
                val t = System.nanoTime()
                val buf = ByteArray(16)
                buf[0] = (xb ushr 24).toByte(); buf[1] = (xb ushr 16).toByte()
                buf[2] = (xb ushr 8).toByte();  buf[3] = xb.toByte()
                buf[4] = (yb ushr 24).toByte(); buf[5] = (yb ushr 16).toByte()
                buf[6] = (yb ushr 8).toByte();  buf[7] = yb.toByte()
                buf[8] = (zb ushr 24).toByte(); buf[9] = (zb ushr 16).toByte()
                buf[10] = (zb ushr 8).toByte(); buf[11] = zb.toByte()
                buf[12] = (t ushr 24).toByte(); buf[13] = (t ushr 16).toByte()
                buf[14] = (t ushr 8).toByte();  buf[15] = t.toByte()
                NativeBridge.addEntropy(buf)
            }
            override fun onAccuracyChanged(s: Sensor?, a: Int) {}
        }
        if (accel != null) {
            sm.registerListener(listener, accel, SensorManager.SENSOR_DELAY_GAME)
        }
        onDispose { sm?.unregisterListener(listener) }
    }

    // ---- 随机池快照轮询：驱动 hex 网格跳动 ----
    LaunchedEffect(Unit) {
        while (true) {
            val snap = NativeBridge.randomPoolSnapshot()
            if (snap.isNotEmpty()) {
                val sb = StringBuilder(snap.size * 2 + snap.size / 16)
                for (i in snap.indices) {
                    val v = snap[i].toInt() and 0xFF
                    sb.append(HEX[v ushr 4]).append(HEX[v and 0xF])
                    // 每 16 字节换行，排成整齐网格。
                    if (i % 16 == 15) sb.append('\n') else sb.append(' ')
                }
                poolHex = sb.toString()
            }
            delay(80)
        }
    }

    // ---- 空闲微搅动：对齐桌面 VC，无涂抹/传感器事件时也持续补喂真熵 ----
    // 每 200ms 用系统真熵源（nanoTime 低位 + elapsedRealtimeNanos 低位）补喂 8B，
    // 触发 native Randmix 搅拌 → 池真在变，hex 快照自然跳动。这是「持续搅拌」而非假动画：
    // 喂的是真实时间抖动熵，不是 Random() 伪随机。不影响 ENTROPY_TARGET 放行门槛（涂抹计）。
    LaunchedEffect(Unit) {
        while (true) {
            val t1 = System.nanoTime()
            val t2 = android.os.SystemClock.elapsedRealtimeNanos()
            val buf = ByteArray(8)
            buf[0] = (t1 ushr 24).toByte(); buf[1] = (t1 ushr 16).toByte()
            buf[2] = (t1 ushr 8).toByte();  buf[3] = t1.toByte()
            buf[4] = (t2 ushr 24).toByte(); buf[5] = (t2 ushr 16).toByte()
            buf[6] = (t2 ushr 8).toByte();  buf[7] = t2.toByte()
            NativeBridge.addEntropy(buf)
            delay(200)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.create_entropy_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = !busy) {
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
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.create_entropy_fullscreen_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                if (hasSensor) stringResource(R.string.create_entropy_sensor_on)
                else stringResource(R.string.create_entropy_sensor_none),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ---- 随机池 hex 网格：跳动的「加密流」，对齐桌面 VeraCrypt Random Pool ----
            Text(
                stringResource(R.string.create_entropy_pool_label),
                style = MaterialTheme.typography.labelLarge,
            )
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(8.dp),
            ) {
                Text(
                    text = poolHex,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.primary,
                    lineHeight = 13.sp,
                )
            }

            // ---- 进度 ----
            LinearProgressIndicator(
                progress = { (swipeCount.toFloat() / ENTROPY_TARGET).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                if (entropyReady) stringResource(R.string.create_entropy_done)
                else stringResource(R.string.create_entropy_progress, swipeCount * 100 / ENTROPY_TARGET),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ---- 全屏涂抹区：占满剩余空间，收集触点熵 ----
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .clip(RoundedCornerShape(12.dp))
                    .background(
                        if (entropyReady) MaterialTheme.colorScheme.secondaryContainer
                        else MaterialTheme.colorScheme.surfaceVariant
                    )
                    .pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                val event = awaitPointerEvent()
                                val ptr = event.changes.firstOrNull() ?: continue
                                val xb = ptr.position.x.toRawBits()
                                val yb = ptr.position.y.toRawBits()
                                val t = System.nanoTime()
                                val buf = ByteArray(12)
                                buf[0] = (xb ushr 24).toByte(); buf[1] = (xb ushr 16).toByte()
                                buf[2] = (xb ushr 8).toByte();  buf[3] = xb.toByte()
                                buf[4] = (yb ushr 24).toByte(); buf[5] = (yb ushr 16).toByte()
                                buf[6] = (yb ushr 8).toByte();  buf[7] = yb.toByte()
                                buf[8] = (t ushr 24).toByte();  buf[9] = (t ushr 16).toByte()
                                buf[10] = (t ushr 8).toByte();  buf[11] = t.toByte()
                                NativeBridge.addEntropy(buf)
                                if (swipeState.value < ENTROPY_TARGET) swipeState.value++
                            }
                        }
                    },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (entropyReady) stringResource(R.string.create_entropy_done)
                    else stringResource(R.string.create_entropy_swipe_here),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            if (message != null) {
                Text(
                    message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // ---- 创建 ----
            if (busy) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    CircularProgressIndicator(modifier = Modifier.height(20.dp))
                    Text(
                        stringResource(R.string.create_in_progress),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            } else {
                Button(
                    onClick = onCreate,
                    enabled = entropyReady,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.create_submit))
                }
            }
            Spacer(Modifier.height(4.dp))
        }
    }
}

private val HEX = "0123456789abcdef".toCharArray()
