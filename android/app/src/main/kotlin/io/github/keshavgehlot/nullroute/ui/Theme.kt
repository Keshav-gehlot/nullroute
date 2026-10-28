package io.github.keshavgehlot.nullroute.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Same tokens as the browser extension so the products read as one family.
private val Route = Color(0xFF2F5BEA)
private val RouteDark = Color(0xFF7B9BFF)
private val Ink = Color(0xFF1B2333)
private val Paper = Color(0xFFEEF1F6)
private val Signal = Color(0xFFB7790A)
private val SignalDark = Color(0xFFF2BD4B)

val BlockedColorLight = Color(0xFFB42318)
val BlockedColorDark = Color(0xFFFF8A80)

private val Light = lightColorScheme(
    primary = Route,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDFE7FD),
    onPrimaryContainer = Ink,
    secondary = Color(0xFF5D677A),
    tertiary = Signal,
    tertiaryContainer = Color(0xFFFDF1D8),
    onTertiaryContainer = Color(0xFF4A3104),
    background = Paper,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
    surfaceVariant = Color(0xFFE4E8F0),
    onSurfaceVariant = Color(0xFF5D677A),
    outline = Color(0xFFD5DBE5),
    surfaceContainer = Color(0xFFF6F8FB),
    error = BlockedColorLight,
)

private val Dark = darkColorScheme(
    primary = RouteDark,
    onPrimary = Color(0xFF0B1638),
    primaryContainer = Color(0xFF22305A),
    onPrimaryContainer = Color(0xFFE7EBF3),
    secondary = Color(0xFF9AA4B8),
    tertiary = SignalDark,
    tertiaryContainer = Color(0xFF3A2F16),
    onTertiaryContainer = Color(0xFFF7E3B5),
    background = Color(0xFF121826),
    onBackground = Color(0xFFE7EBF3),
    surface = Color(0xFF1A2234),
    onSurface = Color(0xFFE7EBF3),
    surfaceVariant = Color(0xFF232C40),
    onSurfaceVariant = Color(0xFF9AA4B8),
    outline = Color(0xFF2B354B),
    surfaceContainer = Color(0xFF1A2234),
    error = BlockedColorDark,
)

@Composable
fun NullRouteTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) Dark else Light, content = content)
}
