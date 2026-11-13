// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.outlined.AddCircleOutline
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.PeopleAlt
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/** Where a [MenuScreen] row leads. */
enum class MenuItem { ManageCredentials, ShareInPerson, History, AddCredentials, RecentErrors, Settings, About, Verify, Logout }

fun menuItemTestTag(item: MenuItem) = "menu_${item.name}"

/**
 * The wallet's menu: every destination in one list, Logout set apart below a
 * rule, and the attribution line at the foot. [current] highlights the row of
 * the screen the user came from.
 *
 * [MenuItem.Verify] opens the sample app's mdoc reader. It is this app's own
 * addition to the designed list, which describes the holder side only.
 */
@Composable
fun MenuScreen(current: MenuItem?, onSelect: (MenuItem) -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = ScreenMargin),
    ) {
        Spacer(modifier = Modifier.height(20.dp))
        MenuRow(MenuItem.ManageCredentials, ImageVector.vectorResource(R.drawable.ic_wallet), R.string.home_manage_credentials, current, onSelect)
        MenuRow(MenuItem.ShareInPerson, Icons.Outlined.PeopleAlt, R.string.home_share_in_person, current, onSelect)
        MenuRow(MenuItem.History, Icons.Outlined.History, R.string.menu_history, current, onSelect)
        MenuRow(MenuItem.AddCredentials, Icons.Outlined.AddCircleOutline, R.string.add_credential_title, current, onSelect)
        MenuRow(MenuItem.RecentErrors, Icons.Outlined.ErrorOutline, R.string.menu_recent_errors, current, onSelect)
        MenuRow(MenuItem.Settings, Icons.Outlined.Settings, R.string.nav_settings, current, onSelect)
        MenuRow(MenuItem.About, Icons.Outlined.Info, R.string.menu_about, current, onSelect)
        MenuRow(MenuItem.Verify, Icons.Outlined.VerifiedUser, R.string.menu_verify, current, onSelect)
        Spacer(modifier = Modifier.height(20.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.outline)
        Spacer(modifier = Modifier.height(20.dp))
        MenuRow(MenuItem.Logout, Icons.AutoMirrored.Filled.Logout, R.string.menu_logout, current, onSelect)
        Spacer(modifier = Modifier.weight(1f).height(40.dp))
        HorizontalDivider(color = MaterialTheme.colorScheme.outline)
        Text(
            text = stringResource(R.string.menu_powered_by),
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 20.dp),
        )
    }
}

@Composable
private fun MenuRow(item: MenuItem, icon: ImageVector, label: Int, current: MenuItem?, onSelect: (MenuItem) -> Unit) {
    val shape = RoundedCornerShape(CardCorner)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            .then(if (item == current) Modifier.background(MaterialTheme.colorScheme.surfaceContainerHigh, shape) else Modifier)
            .clickable(role = Role.Button) { onSelect(item) }
            .testTag(menuItemTestTag(item))
            .padding(horizontal = 12.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onBackground, modifier = Modifier.size(24.dp))
        Spacer(modifier = Modifier.width(10.dp))
        Text(stringResource(label), style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
    }
}
