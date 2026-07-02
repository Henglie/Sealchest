package com.henglie.sealchest

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.henglie.sealchest.crypto.NativeBridge
import com.henglie.sealchest.fs.FatFileSystem
import com.henglie.sealchest.fs.MountManager
import com.henglie.sealchest.ui.theme.SealchestTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SealchestTheme {
                HomeScreen()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // 进程还在但 Activity 销毁时不主动上锁：DocumentsProvider 可能仍在被别的 app
        // 读取挂载中的文件。真正上锁由用户显式触发或进程死亡（密钥随内存释放）。
    }
}

/** PRF 选项：显示名 + 传给 native 的 ID（0=自动）。 */
private val PRF_OPTIONS = listOf(
    "自动检测" to NativeBridge.PRF_AUTO,
    "SHA-512" to 1,
    "Whirlpool" to 2,
    "SHA-256" to 3,
    "BLAKE2s" to 4,
    "Streebog" to 5,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // 挂载态用 mountId 触发重组：unlock/lock 后自增。
    var mountToken by remember { mutableStateOf(0) }
    val mount = remember(mountToken) { MountManager.currentMount() }

    // 选中的待解锁容器。
    var pickedUri by remember { mutableStateOf<Uri?>(null) }
    var pickedName by remember { mutableStateOf("") }

    var password by remember { mutableStateOf("") }
    var pim by remember { mutableStateOf("") }
    var prfIndex by remember { mutableStateOf(0) }

    var unlocking by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            // 持久化读权限，供 DocumentsProvider 后续跨进程读容器密文。
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            pickedUri = uri
            pickedName = queryDisplayName(context, uri) ?: uri.lastPathSegment ?: "容器"
            error = null
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.home_title)) }) },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.home_subtitle),
                style = MaterialTheme.typography.titleMedium,
            )

            if (!NativeBridge.isAvailable) {
                Text(
                    text = stringResource(R.string.native_unavailable),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyLarge,
                )
                return@Column
            }

            val m = mount
            if (m != null && !m.closed) {
                // ---- 已挂载态 ----
                MountedPanel(
                    fs = m.fs,
                    displayName = m.displayName,
                    onBrowse = { launchBrowse(context) },
                    onLock = {
                        MountManager.lock()
                        mountToken++
                        pickedUri = null
                        password = ""
                    },
                )
            } else {
                // ---- 未挂载态：选容器 + 解锁 ----
                OutlinedButton(
                    onClick = { picker.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (pickedUri == null) stringResource(R.string.home_pick_container)
                        else pickedName
                    )
                }

                if (pickedUri != null) {
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it; error = null },
                        label = { Text(stringResource(R.string.unlock_password)) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = pim,
                        onValueChange = { pim = it.filter(Char::isDigit); error = null },
                        label = { Text(stringResource(R.string.unlock_pim)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(
                        stringResource(R.string.unlock_prf),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        PRF_OPTIONS.forEachIndexed { i, (label, _) ->
                            if (i <= 3) FilterChip(
                                selected = prfIndex == i,
                                onClick = { prfIndex = i },
                                label = { Text(label) },
                            )
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        PRF_OPTIONS.forEachIndexed { i, (label, _) ->
                            if (i >= 4) FilterChip(
                                selected = prfIndex == i,
                                onClick = { prfIndex = i },
                                label = { Text(label) },
                            )
                        }
                    }

                    if (error != null) {
                        Text(
                            error!!,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }

                    Button(
                        onClick = {
                            val uri = pickedUri ?: return@Button
                            unlocking = true
                            error = null
                            val pw = password.toByteArray(Charsets.UTF_8)
                            val pimVal = pim.toIntOrNull() ?: 0
                            val prfVal = PRF_OPTIONS[prfIndex].second
                            scope.launch {
                                val result = withContext(Dispatchers.IO) {
                                    runCatching {
                                        MountManager.unlock(
                                            context, uri, pickedName, pw, pimVal, prfVal
                                        )
                                    }
                                }
                                pw.fill(0)
                                unlocking = false
                                result.onSuccess {
                                    password = ""
                                    mountToken++
                                }.onFailure {
                                    error = it.message
                                        ?: context.getString(R.string.unlock_wrong)
                                }
                            }
                        },
                        enabled = !unlocking && password.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        if (unlocking) {
                            CircularProgressIndicator(
                                modifier = Modifier.height(20.dp),
                                strokeWidth = 2.dp,
                            )
                            Spacer(Modifier.height(0.dp))
                            Text("  " + stringResource(R.string.unlock_unlocking))
                        } else {
                            Text(stringResource(R.string.unlock_submit))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MountedPanel(
    fs: FatFileSystem,
    displayName: String,
    onBrowse: () -> Unit,
    onLock: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.LockOpen, contentDescription = null)
                Spacer(Modifier.height(0.dp))
                Text(
                    "  $displayName",
                    style = MaterialTheme.typography.titleLarge,
                )
            }
            val label = fs.volumeLabel.ifBlank { "（无卷标）" }
            Text("文件系统：${fs.fatType}", style = MaterialTheme.typography.bodyMedium)
            Text("卷标：$label", style = MaterialTheme.typography.bodyMedium)
        }
    }

    Spacer(Modifier.height(8.dp))

    Button(onClick = onBrowse, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.browse_title))
    }

    OutlinedButton(onClick = onLock, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Filled.Lock, contentDescription = null)
        Text("  " + stringResource(R.string.browse_lock))
    }
}

/** 用系统文件界面浏览已挂载卷的根。authority 与 Manifest 一致（含 debug 后缀）。 */
private fun launchBrowse(context: android.content.Context) {
    val authority = context.packageName + ".documents"
    val rootUri = DocumentsContract.buildRootUri(authority, "sealchest-root")
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(rootUri, DocumentsContract.Root.MIME_TYPE_ITEM)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    runCatching { context.startActivity(intent) }
}

/** 从 SAF URI 查显示名。 */
private fun queryDisplayName(context: android.content.Context, uri: Uri): String? {
    return context.contentResolver.query(
        uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null
    )?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }
}
