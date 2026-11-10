// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.outlined.AddCircleOutline
import androidx.compose.material.icons.outlined.Badge
import androidx.compose.material.icons.outlined.PeopleAlt
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp

const val HOME_ATTENTION_TAG = "home_attention"
const val HOME_MANAGE_TAG = "home_manage_credentials"
const val HOME_SHARE_TAG = "home_share_in_person"

/**
 * The wallet's landing screen: a brand-blue hero greeting the user, a banner
 * when credentials need attention, and the two things a wallet is for - manage
 * what you hold, and share it with someone in front of you. Scanning a QR code
 * is the centre button of the bottom bar on every screen, so it has no tile
 * here.
 *
 * [attentionCount] is how many credentials cannot currently be used (see
 * [needsAttention]); the banner opens Manage credentials on that filter.
 * [showAddCredentials] is the dismissible prompt to the Add Credentials
 * screen. [showPhotoIdOnboarding] offers the Photo ID scan directly - the
 * caller decides when (a sample-app setting, combined with the wallet not
 * already holding a Photo ID; see [WalletViewModel.showPhotoIdOnboarding]).
 */
@Composable
fun HomeScreen(
    displayName: String?,
    attentionCount: Int,
    onShowAttention: () -> Unit,
    onManageCredentials: () -> Unit,
    onShareInPerson: () -> Unit,
    showAddCredentials: Boolean,
    onAddCredentials: () -> Unit,
    onDismissAddCredentials: () -> Unit,
    modifier: Modifier = Modifier,
    showPhotoIdOnboarding: Boolean = false,
    onStartPhotoIdOnboarding: () -> Unit = {},
) {
    val brand = MaterialTheme.colorScheme.primaryContainer
    Column(modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(brand)
                .padding(horizontal = ScreenMargin)
                .padding(top = 28.dp, bottom = 28.dp),
        ) {
            Text(
                text = if (displayName.isNullOrBlank()) {
                    stringResource(R.string.home_welcome_back)
                } else {
                    stringResource(R.string.home_welcome_back_name, displayName)
                },
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            if (attentionCount > 0) {
                Spacer(modifier = Modifier.height(28.dp))
                AttentionBanner(count = attentionCount, onClick = onShowAttention)
            }
        }
        // The hero ends halfway down the two tiles, which straddle its edge.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .drawBehind { drawRect(brand, size = Size(size.width, size.height / 2)) }
                .padding(horizontal = ScreenMargin),
            horizontalArrangement = Arrangement.spacedBy(32.dp),
        ) {
            HomeTile(
                icon = ImageVector.vectorResource(R.drawable.ic_wallet),
                label = stringResource(R.string.home_manage_credentials),
                onClick = onManageCredentials,
                modifier = Modifier.weight(1f).testTag(HOME_MANAGE_TAG),
            )
            HomeTile(
                icon = Icons.Outlined.PeopleAlt,
                label = stringResource(R.string.home_share_in_person),
                onClick = onShareInPerson,
                modifier = Modifier.weight(1f).testTag(HOME_SHARE_TAG),
            )
        }
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = ScreenMargin, vertical = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (showPhotoIdOnboarding) {
                HomePromptCard(
                    icon = Icons.Outlined.Badge,
                    title = stringResource(R.string.home_photo_id_onboarding_title),
                    text = stringResource(R.string.home_photo_id_onboarding_description),
                    action = stringResource(R.string.home_prompt_begin),
                    onAction = onStartPhotoIdOnboarding,
                    onDismiss = null,
                )
            }
            if (showAddCredentials) {
                HomePromptCard(
                    icon = Icons.Outlined.AddCircleOutline,
                    title = stringResource(R.string.add_credential_title),
                    text = stringResource(R.string.home_add_credentials_text),
                    action = stringResource(R.string.home_prompt_get_started),
                    onAction = onAddCredentials,
                    onDismiss = onDismissAddCredentials,
                )
            }
        }
    }
}

@Composable
private fun AttentionBanner(count: Int, onClick: () -> Unit) {
    OutlinedCard(
        modifier = Modifier.fillMaxWidth().testTag(HOME_ATTENTION_TAG),
        onClick = onClick,
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Outlined.WarningAmber,
                contentDescription = null,
                tint = SirosDesign.attention,
                modifier = Modifier.size(40.dp),
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = if (count == 1) {
                    stringResource(R.string.home_attention_one)
                } else {
                    stringResource(R.string.home_attention_other, count)
                },
                style = MaterialTheme.typography.titleSmall,
                color = SirosDesign.brandOnPage,
                modifier = Modifier.weight(1f),
            )
            Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = SirosDesign.brandOnPage,
                modifier = Modifier.size(28.dp),
            )
        }
    }
}

@Composable
private fun HomeTile(icon: ImageVector, label: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    OutlinedCard(modifier = modifier.heightIn(min = 180.dp), onClick = onClick) {
        Column(
            modifier = Modifier.fillMaxWidth().heightIn(min = 148.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(icon, contentDescription = null, tint = SirosDesign.brandOnPage, modifier = Modifier.size(64.dp))
            Spacer(modifier = Modifier.height(16.dp))
            Text(label, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, textAlign = TextAlign.Center)
        }
    }
}

/** A prompt card: grey icon tile, a title, a sentence and an underlined action; [onDismiss] adds the close cross. */
@Composable
private fun HomePromptCard(
    icon: ImageVector,
    title: String,
    text: String,
    action: String,
    onAction: () -> Unit,
    onDismiss: (() -> Unit)?,
) {
    OutlinedCard(modifier = Modifier.fillMaxWidth(), onClick = onAction, contentPadding = PaddingValues(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(56.dp)
                    .background(MaterialTheme.colorScheme.surfaceContainer, RoundedCornerShape(4.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = SirosDesign.brandOnPage, modifier = Modifier.size(36.dp))
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(text, style = MaterialTheme.typography.bodyMedium)
                Text(
                    action,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    textDecoration = TextDecoration.Underline,
                    modifier = Modifier.clickable(onClick = onAction),
                )
            }
            if (onDismiss != null) {
                IconButton(onClick = onDismiss, modifier = Modifier.align(Alignment.Top).size(36.dp)) {
                    Icon(Icons.Filled.Close, contentDescription = stringResource(R.string.home_prompt_dismiss))
                }
            }
        }
    }
}
