package com.henglie.sealchest.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val LightColors = lightColorScheme(
    primary = md_light_primary,
    onPrimary = md_light_onPrimary,
    primaryContainer = md_light_primaryContainer,
    onPrimaryContainer = md_light_onPrimaryContainer,
    secondary = md_light_secondary,
    onSecondary = md_light_onSecondary,
    secondaryContainer = md_light_secondaryContainer,
    onSecondaryContainer = md_light_onSecondaryContainer,
    background = md_light_background,
    onBackground = md_light_onBackground,
    surface = md_light_surface,
    onSurface = md_light_onSurface,
    surfaceVariant = md_light_surfaceVariant,
    onSurfaceVariant = md_light_onSurfaceVariant,
    error = md_light_error,
    onError = md_light_onError,
    outline = md_light_outline,
)

private val DarkColors = darkColorScheme(
    primary = md_dark_primary,
    onPrimary = md_dark_onPrimary,
    primaryContainer = md_dark_primaryContainer,
    onPrimaryContainer = md_dark_onPrimaryContainer,
    secondary = md_dark_secondary,
    onSecondary = md_dark_onSecondary,
    secondaryContainer = md_dark_secondaryContainer,
    onSecondaryContainer = md_dark_onSecondaryContainer,
    background = md_dark_background,
    onBackground = md_dark_onBackground,
    surface = md_dark_surface,
    onSurface = md_dark_onSurface,
    surfaceVariant = md_dark_surfaceVariant,
    onSurfaceVariant = md_dark_onSurfaceVariant,
    error = md_dark_error,
    onError = md_dark_onError,
    outline = md_dark_outline,
)

/**
 * 匿匣主题。谷歌原生 M3：
 *  - [primaryColor] == 0（跟随系统）：Android 12（API 31）+ 走动态取色（Material You，
 *    跟随壁纸）；以下走靛蓝兜底配色。整套配色一致，不叠加固定强调色。
 *  - [primaryColor] != 0（用户选了固定预设色）：关动态取色，用兜底配色 + 该色覆盖 primary。
 *    避免「动态取色其余角色 + 固定 primary」两套色同时存在的割裂。
 */
@Composable
fun SealchestTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    primaryColor: Int = 0,
    content: @Composable () -> Unit,
) {
    val followSystemColor = primaryColor == 0
    val colorScheme = when {
        // 跟随系统 + API 31+：动态取色，整套一致。
        followSystemColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val ctx = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }
    // 用户选了固定预设色 → 仅覆盖 primary，其余保留兜底配色（此时未走动态取色，无割裂）。
    val finalScheme = if (!followSystemColor) colorScheme.copy(primary = Color(primaryColor)) else colorScheme

    MaterialTheme(
        colorScheme = finalScheme,
        typography = Typography,
        content = content,
    )
}
