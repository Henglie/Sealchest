package com.henglie.sealchest

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.henglie.sealchest.crypto.NativeBridge
import com.henglie.sealchest.ui.theme.SealchestTheme

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
}

/**
 * 第一版占位主屏：显示 native 自检结果，验证「中文路径 + NDK + AGP」工具链通了。
 * 后续替换为「选容器 → 输密码 → 浏览文件」流程。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen() {
    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.app_name)) }) },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val nativeOk = NativeBridge.isAvailable
            Text(
                text = stringResource(R.string.app_tagline),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                text = if (nativeOk) {
                    stringResource(R.string.native_ready)
                } else {
                    stringResource(R.string.native_missing)
                },
                style = MaterialTheme.typography.bodyLarge,
            )
            if (nativeOk) {
                Text(
                    text = stringResource(R.string.native_version, NativeBridge.version()),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}
