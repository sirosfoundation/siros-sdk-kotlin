// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.outlined.AccountCircle
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/** The three slots of the bottom bar every main screen carries. */
enum class WalletNavItem { Home, ScanQr, Menu }

/** Horizontal page margin shared by every screen of the design (24 of its 440 units). */
val ScreenMargin = 24.dp

/** Corner radius of the design's cards, tiles, panels and buttons. */
val CardCorner = 8.dp

/**
 * The frame every signed-in screen sits in: the wallet header on top, the
 * screen's own content, and either the Home / Scan QR / Menu bar or a single
 * Back button underneath.
 *
 * [onBack] non-null selects the Back button - the design uses it for the
 * full-attention screens (camera, QR display, NFC tap) where the three-way bar
 * would compete with the one thing the user is doing. [brandHeader] paints the
 * header in brand blue so Home's hero continues up behind it.
 */
@Composable
fun WalletChrome(
    displayName: String?,
    selected: WalletNavItem?,
    onHome: () -> Unit,
    onScanQr: () -> Unit,
    onMenu: () -> Unit,
    onAccount: () -> Unit,
    modifier: Modifier = Modifier,
    brandHeader: Boolean = false,
    onBack: (() -> Unit)? = null,
    onBottomBarHeight: (Int) -> Unit = {},
    content: @Composable () -> Unit,
) {
    // Over the brand-blue header the status bar's icons are light in either
    // theme; elsewhere they follow the page (see SirosTheme).
    val pageIsLight = MaterialTheme.colorScheme.background.luminance() > 0.5f
    StatusBarIcons(dark = pageIsLight && !brandHeader)
    // The frame paints its own background, so it also sets the colour text
    // on it defaults to - in either theme, wherever the frame is hosted.
    CompositionLocalProvider(LocalContentColor provides MaterialTheme.colorScheme.onBackground) {
        Column(modifier = modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
            WalletHeader(displayName = displayName, onBrand = brandHeader, onAccount = onAccount)
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) { content() }
            Box(modifier = Modifier.onGloballyPositioned { onBottomBarHeight(it.size.height) }) {
                if (onBack != null) {
                    BackBar(onBack = onBack)
                } else {
                    WalletBottomBar(selected = selected, onHome = onHome, onScanQr = onScanQr, onMenu = onMenu)
                }
            }
        }
    }
}

/** Mark and product name on the left, the signed-in user's wallet on the right. */
@Composable
fun WalletHeader(displayName: String?, onBrand: Boolean, onAccount: () -> Unit) {
    val background = if (onBrand) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.background
    val foreground = if (onBrand) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onBackground
    Column(modifier = Modifier.fillMaxWidth().background(background).statusBarsPadding()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = ScreenMargin, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Image(
                painter = painterResource(R.drawable.ic_siros_mark),
                contentDescription = stringResource(R.string.topbar_logo_description),
                modifier = Modifier
                    .size(28.dp)
                    .then(if (onBrand) Modifier.border(1.5.dp, foreground, CircleShape) else Modifier),
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.topbar_title),
                style = MaterialTheme.typography.titleSmall,
                color = foreground,
                maxLines = 1,
            )
            Spacer(modifier = Modifier.weight(1f).width(12.dp))
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(CardCorner))
                    .clickable(role = Role.Button, onClick = onAccount)
                    .padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.AccountCircle, contentDescription = null, tint = foreground, modifier = Modifier.size(24.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (displayName.isNullOrBlank()) {
                        stringResource(R.string.header_my_wallet)
                    } else {
                        stringResource(R.string.header_wallet_of, displayName)
                    },
                    style = MaterialTheme.typography.bodyLarge,
                    color = foreground,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (!onBrand) HorizontalDivider(color = MaterialTheme.colorScheme.outline)
    }
}

const val NAV_HOME_TAG = "nav_home"
const val NAV_SCAN_QR_TAG = "nav_scan_qr"
const val NAV_MENU_TAG = "nav_menu"

/** Home, Scan QR (the raised black button) and Menu. */
@Composable
fun WalletBottomBar(selected: WalletNavItem?, onHome: () -> Unit, onScanQr: () -> Unit, onMenu: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.background)
            .padding(top = 8.dp, bottom = 12.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.Bottom,
    ) {
        BottomBarItem(
            label = stringResource(R.string.nav_home),
            selected = selected == WalletNavItem.Home,
            onClick = onHome,
            tag = NAV_HOME_TAG,
        ) { tint -> Icon(Icons.Outlined.Home, contentDescription = null, tint = tint, modifier = Modifier.size(32.dp)) }
        BottomBarItem(
            label = stringResource(R.string.nav_scan_qr),
            selected = selected == WalletNavItem.ScanQr,
            onClick = onScanQr,
            tag = NAV_SCAN_QR_TAG,
        ) {
            Box(
                modifier = Modifier.size(48.dp).background(SirosDesign.scanButton, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Filled.QrCode2, contentDescription = null, tint = SirosDesign.onScanButton, modifier = Modifier.size(26.dp))
            }
        }
        BottomBarItem(
            label = stringResource(R.string.nav_menu),
            selected = selected == WalletNavItem.Menu,
            onClick = onMenu,
            tag = NAV_MENU_TAG,
        ) { tint -> Icon(Icons.Filled.Menu, contentDescription = null, tint = tint, modifier = Modifier.size(32.dp)) }
    }
}

@Composable
private fun BottomBarItem(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    tag: String,
    icon: @Composable (tint: Color) -> Unit,
) {
    val tint = if (selected) MaterialTheme.colorScheme.onBackground else SirosDesign.secondaryText
    Column(
        modifier = Modifier
            .width(96.dp)
            .clip(RoundedCornerShape(CardCorner))
            .clickable(role = Role.Tab, onClick = onClick)
            .testTag(tag)
            .padding(vertical = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(modifier = Modifier.height(48.dp), contentAlignment = Alignment.Center) { icon(tint) }
        Spacer(modifier = Modifier.height(4.dp))
        Text(text = label, style = MaterialTheme.typography.labelLarge, color = tint)
    }
}

/** The single full-width Back button that replaces the bottom bar on full-attention screens. */
@Composable
fun BackBar(onBack: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background)) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outline)
        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 16.dp).height(48.dp),
            shape = RoundedCornerShape(CardCorner),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            colors = androidx.compose.material3.ButtonDefaults.outlinedButtonColors(
                containerColor = SirosDesign.altSurface,
                contentColor = MaterialTheme.colorScheme.onSurface,
            ),
        ) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(10.dp))
            Text(stringResource(R.string.nav_back), style = MaterialTheme.typography.titleSmall)
        }
    }
}

/**
 * A screen's heading with the rule under it. With [onBack] it becomes the
 * smaller "arrow + title" heading of a screen one step down from a main one.
 */
@Composable
fun ScreenTitle(text: String, modifier: Modifier = Modifier, onBack: (() -> Unit)? = null) {
    Column(modifier = modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp, bottom = 8.dp)) {
            if (onBack != null) {
                IconButton(onClick = onBack, modifier = Modifier.size(40.dp)) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.nav_back))
                }
                Spacer(modifier = Modifier.width(4.dp))
            }
            Text(
                text = text,
                style = if (onBack != null) MaterialTheme.typography.headlineSmall else MaterialTheme.typography.headlineLarge,
                color = MaterialTheme.colorScheme.onBackground,
            )
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    }
}

/** The design's bordered white card. */
@Composable
fun OutlinedCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    container: Color = MaterialTheme.colorScheme.surface,
    contentPadding: PaddingValues = PaddingValues(16.dp),
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(CardCorner))
            .background(container)
            .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(CardCorner))
            .then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .padding(contentPadding),
    ) { content() }
}

/** A square brand-blue tile holding a white icon - the lead of an action card. */
@Composable
fun BrandIconTile(icon: ImageVector, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier.size(64.dp).background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(4.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onPrimaryContainer, modifier = Modifier.size(34.dp))
    }
}

/** A pale-blue tile holding a brand-blue icon - the lead of an informational row. */
@Composable
fun SoftIconTile(icon: ImageVector, modifier: Modifier = Modifier, shape: androidx.compose.ui.graphics.Shape = RoundedCornerShape(4.dp)) {
    Box(
        modifier = modifier.size(44.dp).background(MaterialTheme.colorScheme.secondaryContainer, shape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSecondaryContainer, modifier = Modifier.size(24.dp))
    }
}

/**
 * An action card: title, one line of explanation, and a brand tile. The tile
 * leads and a chevron trails ([tileLeading], Share in-person), or the tile
 * trails on its own (Add Credentials).
 */
@Composable
fun ActionCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    tileLeading: Boolean = false,
) {
    OutlinedCard(modifier = modifier.fillMaxWidth(), onClick = onClick, contentPadding = PaddingValues(14.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (tileLeading) {
                BrandIconTile(icon)
                Spacer(modifier = Modifier.width(16.dp))
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                Spacer(modifier = Modifier.height(2.dp))
                Text(subtitle, style = MaterialTheme.typography.bodyLarge, color = SirosDesign.secondaryText)
            }
            Spacer(modifier = Modifier.width(12.dp))
            if (tileLeading) {
                Icon(
                    Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    tint = SirosDesign.brandOnPage,
                    modifier = Modifier.size(28.dp),
                )
            } else {
                BrandIconTile(icon)
            }
        }
    }
}

/**
 * The brand-blue panel of the full-attention screens: one focal element (a
 * camera view, a QR code, the NFC mark), a rule, and one line of instruction.
 */
@Composable
fun BrandPanel(caption: String, modifier: Modifier = Modifier, focus: @Composable () -> Unit) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(4.dp))
            .padding(horizontal = 40.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        focus()
        Spacer(modifier = Modifier.height(24.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.onPrimaryContainer)
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = caption,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(8.dp))
    }
}
