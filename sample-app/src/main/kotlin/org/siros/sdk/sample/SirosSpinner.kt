// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * SIROS-branded loading spinner, visually matching wallet-frontend's
 * `Spinner.jsx` (see `src/components/Shared/Spinner.jsx`): a brand-colored
 * ring with a gap - reproducing lucide-react's `loader-circle` icon, which
 * wallet-frontend spins continuously via Tailwind's `animate-spin`
 * (linear, 1 rotation/second, infinite) - overlaid with the static SIROS
 * mark scaled down and centered, reusing this app's existing
 * `ic_siros_mark` drawable (already the same navy `#1C4587` used in
 * wallet-frontend's `branding/default/theme.json` brand color).
 *
 * The ring's rotation is a self-contained infinite Compose animation, not
 * driven by [progress] or any app state - so unlike the old
 * `LinearProgressIndicator` it replaces, it structurally cannot sit frozen
 * while a long-running step (e.g. native ZK proof compute) has nothing new
 * to report. [progress] (0f..1f, or null while indeterminate - typically
 * fed from [FlowProgressAnimator.displayProgress]) is instead shown as a
 * thin background progress track behind the spinning ring, so real
 * (ticker-smoothed, monotonic) completion information isn't lost even
 * though the spin itself never encodes it.
 */
@Composable
fun SirosSpinner(
    progress: Float?,
    modifier: Modifier = Modifier,
    size: Dp = 96.dp,
) {
    val infiniteTransition = rememberInfiniteTransition(label = "siros-spinner-rotation")
    val rotationDegrees by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1000, easing = LinearEasing)),
        label = "siros-spinner-rotation-angle",
    )

    val ringColor = MaterialTheme.colorScheme.primary
    val trackColor = MaterialTheme.colorScheme.outlineVariant

    Box(modifier = modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.size(size)) {
            // strokeWidth = 1 in lucide's 24-unit viewBox -> ~1/24th of the diameter.
            val strokeWidth = (this.size.minDimension / 24f).coerceAtLeast(1.5.dp.toPx())
            val inset = strokeWidth / 2f
            val arcSize = Size(this.size.width - strokeWidth, this.size.height - strokeWidth)
            val topLeft = Offset(inset, inset)

            // Background track: real, monotonic progress - present even
            // though the web reference spinner has no such track, so the
            // decoupled progress signal from FlowProgressAnimator isn't
            // discarded by the restyle.
            if (progress != null) {
                drawArc(
                    color = trackColor,
                    startAngle = -90f,
                    sweepAngle = 360f,
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
                )
                drawArc(
                    color = ringColor.copy(alpha = 0.35f),
                    startAngle = -90f,
                    sweepAngle = 360f * progress.coerceIn(0f, 1f),
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
                )
            }

            // The spinning gapped ring itself - lucide's loader-circle is a
            // ~290-degree arc (leaving a ~70-degree gap), rotating clockwise.
            drawArc(
                color = ringColor,
                startAngle = rotationDegrees - 90f,
                sweepAngle = 290f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
            )
        }
        Image(
            painter = painterResource(R.drawable.ic_siros_mark),
            contentDescription = null,
            modifier = Modifier.size(size * 0.55f),
        )
    }
}
