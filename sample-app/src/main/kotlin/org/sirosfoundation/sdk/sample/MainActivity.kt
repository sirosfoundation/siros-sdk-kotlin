package org.sirosfoundation.sdk.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import org.sirosfoundation.sdk.credentials.PresentationRecord
import org.sirosfoundation.sdk.keystore.DestroyMode
import org.sirosfoundation.sdk.keystore.LifecycleState
import org.sirosfoundation.sdk.wallet.WalletState
import android.util.Log
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import org.sirosfoundation.sdk.wallet.DeepLinkType
import org.sirosfoundation.sdk.wallet.classifyDeepLink

class MainActivity : ComponentActivity() {
    private lateinit var viewModel: WalletViewModel
    private val tag = "SIROS_MAIN"
    private var pendingWscaIntent: android.content.Intent? = null

    private fun dispatchIncomingUri(uri: android.net.Uri?) {
        if (uri == null || !::viewModel.isInitialized) return

        Log.i(tag, "Incoming URI: ${uri.scheme}://${uri.host}")
        when (val link = classifyDeepLink(uri, REDIRECT_SCHEME)) {
            is DeepLinkType.AuthCallback -> viewModel.handleAuthRedirect(link.code, link.state)
            is DeepLinkType.CredentialOffer -> viewModel.handleQrResult(link.uri)
            is DeepLinkType.PresentationRequest -> viewModel.handleQrResult(link.uri)
            is DeepLinkType.Unknown -> Log.d(tag, "Ignoring non-wallet URI: ${uri.scheme}://${uri.host}")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Queue WSCA test intent for dispatch after ViewModel is ready
        if (intent?.action == ACTION_WSCA_TEST && BuildConfig.DEBUG) {
            pendingWscaIntent = intent
        }
        val vmFactory = WalletViewModel.Factory(this)
        setContent {
            SirosTheme {
                Surface(
                    modifier = Modifier.fillMaxSize().navigationBarsPadding(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    viewModel = viewModel(factory = vmFactory)
                    LaunchedEffect(Unit) {
                        dispatchIncomingUri(intent?.data)
                        pendingWscaIntent?.let {
                            dispatchWscaTestAction(it)
                            pendingWscaIntent = null
                        }
                    }
                    WalletScreen(viewModel)
                }
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        if (intent.action == ACTION_WSCA_TEST && BuildConfig.DEBUG) {
            if (::viewModel.isInitialized) {
                dispatchWscaTestAction(intent)
            } else {
                pendingWscaIntent = intent
            }
        } else {
            dispatchIncomingUri(intent.data)
        }
    }

    /**
     * Handle WSCA test automation intents (debug builds only).
     *
     * Dispatches to the real ViewModel lifecycle methods — same code path
     * as the UI buttons. Results are emitted via logcat with tag [WSCA_TEST_TAG]
     * so the test harness can parse outcomes.
     *
     * Usage from adb:
     *   adb shell am start -n $PKG/.MainActivity -a org.sirosfoundation.sdk.sample.WSCA_TEST \
     *     --es wsca_action enroll [--es plugin_id r2ps] [--es factor_kind opaque]
     */
    private fun dispatchWscaTestAction(intent: android.content.Intent) {
        if (!::viewModel.isInitialized) {
            Log.e(WSCA_TEST_TAG, """{"action":"error","error":"ViewModel not initialized"}""")
            return
        }
        val action = intent.getStringExtra("wsca_action") ?: run {
            Log.e(WSCA_TEST_TAG, """{"action":"error","error":"missing wsca_action extra"}""")
            return
        }
        Log.i(WSCA_TEST_TAG, """{"action":"$action","status":"dispatching"}""")
        when (action) {
            "enroll" -> viewModel.enrollWscd()
            "rotate" -> viewModel.rotateLifecycle()
            "destroy" -> {
                val modeStr = intent.getStringExtra("mode") ?: "local"
                val mode = when (modeStr) {
                    "revoke" -> DestroyMode.RemoteRevokeIfSupported
                    "strict" -> DestroyMode.Strict
                    else -> DestroyMode.LocalOnly
                }
                viewModel.destroyLifecycle(mode)
            }
            "status" -> viewModel.emitWscaTestStatus()
            "config" -> {
                intent.getStringExtra("plugin_id")?.let {
                    viewModel.selectPlugin(it)
                }
                intent.getStringExtra("r2ps_enabled")?.let {
                    viewModel.updateR2psEnabled(it.toBooleanStrictOrNull() ?: false)
                }
                intent.getStringExtra("r2ps_url")?.let {
                    viewModel.updateR2psServerUrl(it)
                }
                Log.i(WSCA_TEST_TAG, """{"action":"config","status":"applied","plugin_id":"${viewModel.selectedPluginId.value}","r2ps_enabled":${viewModel.r2psEnabled.value},"r2ps_url":"${viewModel.r2psServerUrl.value}"}""")
            }
            "refresh" -> viewModel.refreshWscdInfo()
            else -> Log.e(WSCA_TEST_TAG, """{"action":"error","error":"unknown action: $action"}""")
        }
    }

    companion object {
        private const val REDIRECT_SCHEME = "siros-sample"
        internal const val ACTION_WSCA_TEST = "org.sirosfoundation.sdk.sample.WSCA_TEST"
        internal const val WSCA_TEST_TAG = "WSCA_TEST_RESULT"
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(viewModel: WalletViewModel) {
    val walletState by viewModel.state.collectAsState()
    val backendUrl by viewModel.backendUrl.collectAsState()
    val tenantId by viewModel.tenantId.collectAsState()
    val r2psServerUrl by viewModel.r2psServerUrl.collectAsState()
    val showAddCredential by viewModel.showAddCredential.collectAsState()
    val availableCredentials by viewModel.availableCredentials.collectAsState()
    val isLoadingOffers by viewModel.isLoadingOffers.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val errorMessage by viewModel.errorMessage.collectAsState()
    val presentationHistory by viewModel.presentationHistory.collectAsState()
    val selectedCredential by viewModel.selectedCredential.collectAsState()
    val showHistory by viewModel.showHistory.collectAsState()
    val showQrScanner by viewModel.showQrScanner.collectAsState()
    val pendingPresentation by viewModel.pendingPresentationRequest.collectAsState()

    LaunchedEffect(errorMessage) {
        errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearError()
        }
    }

    // Not logged in → show login screen (no app chrome)
    if (walletState is WalletState.Disconnected || walletState is WalletState.Connecting) {
        LoginScreen(
            backendUrl = backendUrl,
            tenantId = tenantId,
            isLoading = isLoading || walletState is WalletState.Connecting,
            snackbarHostState = snackbarHostState,
            onBackendUrlChange = viewModel::updateBackendUrl,
            onTenantIdChange = viewModel::updateTenantId,
            onLogin = viewModel::login,
            onRegister = viewModel::register,
        )
        return
    }

    // Presentation consent dialog — shown as a full-screen overlay
    if (pendingPresentation != null) {
        PresentationConsentScreen(
            request = pendingPresentation!!,
            onAccept = viewModel::acceptPresentation,
            onDecline = viewModel::declinePresentation,
        )
        return
    }

    // Credential detail sub-screen
    if (selectedCredential != null) {
        CredentialDetailScreen(
            credential = selectedCredential!!,
            onBack = viewModel::closeCredentialDetail,
            onDelete = { viewModel.deleteCredential(selectedCredential!!.id) },
        )
        return
    }

    // Presentation history sub-screen
    if (showHistory) {
        PresentationHistoryScreen(
            history = presentationHistory,
            onBack = viewModel::closeHistory,
        )
        return
    }

    // WSCA developer sub-screen
    val showWscaDeveloper by viewModel.showWscaDeveloper.collectAsState()
    if (showWscaDeveloper) {
        val wscdKeys by viewModel.wscdKeys.collectAsState()
        val wscdLifecycleStatus by viewModel.wscdLifecycleStatus.collectAsState()
        val wscdKeySecurityProps by viewModel.wscdKeySecurityProps.collectAsState()
        val selectedPluginId by viewModel.selectedPluginId.collectAsState()
        WscaDeveloperScreen(
            lifecycleState = viewModel.lifecycleState.collectAsState().value,
            lifecycleStatus = wscdLifecycleStatus,
            keys = wscdKeys,
            keySecurityProps = wscdKeySecurityProps,
            selectedPluginId = selectedPluginId,
            r2psServerUrl = r2psServerUrl,
            onSelectPlugin = viewModel::selectPlugin,
            onR2psServerUrlChange = viewModel::updateR2psServerUrl,
            onEnroll = viewModel::enrollWscd,
            onRotate = viewModel::rotateLifecycle,
            onDestroy = viewModel::destroyLifecycle,
            onRefresh = viewModel::refreshWscdInfo,
            onBack = viewModel::closeWscaDeveloper,
        )
        return
    }

    // QR scanner sub-screen
    if (showQrScanner) {
        QrScannerScreen(
            onQrScanned = viewModel::handleQrResult,
            onBack = viewModel::closeQrScanner,
        )
        return
    }

    // Add credential sub-screen
    if (showAddCredential) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.add_credential_title)) },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                        titleContentColor = MaterialTheme.colorScheme.onSurface,
                    ),
                    navigationIcon = {
                        IconButton(onClick = viewModel::closeAddCredential) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.nav_back))
                        }
                    },
                )
            },
        ) { padding ->
            AddCredentialScreen(
                offers = availableCredentials,
                isLoading = isLoadingOffers,
                onOfferSelected = viewModel::selectCredentialOffer,
                modifier = Modifier.padding(padding),
            )
        }
        return
    }

    // Main app with bottom navigation
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }

    Column(modifier = Modifier.fillMaxSize()) {
        // Top bar
        TopAppBar(
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Image(
                        painter = painterResource(R.drawable.ic_siros_mark),
                        contentDescription = stringResource(R.string.topbar_logo_description),
                        modifier = Modifier.size(28.dp),
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = stringResource(R.string.topbar_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = MaterialTheme.colorScheme.surface,
                titleContentColor = MaterialTheme.colorScheme.onSurface,
            ),
            actions = {
                IconButton(onClick = viewModel::openQrScanner) {
                    Icon(
                        ImageVector.vectorResource(R.drawable.ic_qr_scan),
                        stringResource(R.string.qr_scan_button),
                    )
                }
            },
        )

        // Content area
        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            when (val state = walletState) {
                is WalletState.Ready -> {
                    when (selectedTab) {
                        0 -> CredentialsTab(
                            state = state,
                            onCredentialClick = viewModel::openCredentialDetail,
                            onAddCredential = viewModel::openAddCredential,
                        )
                        2 -> SettingsTab(
                            state = state,
                            backendUrl = backendUrl,
                            tenantId = tenantId,
                            presentationCount = presentationHistory.size,
                            lifecycleState = viewModel.lifecycleState.collectAsState().value,
                            enrollmentInProgress = viewModel.enrollmentInProgress.collectAsState().value,
                            onDisconnect = viewModel::disconnect,
                            onShowHistory = viewModel::openHistory,
                            onEnrollWscd = viewModel::enrollWscd,
                            onShowWscaDeveloper = viewModel::openWscaDeveloper,
                        )
                    }
                }
                is WalletState.FlowActive -> {
                    FlowActiveView(
                        state = state,
                        onCancel = viewModel::cancelCurrentFlow,
                    )
                }
                is WalletState.Error -> {
                    ErrorView(message = state.message, onRetry = viewModel::disconnect)
                }
                else -> { /* Disconnected/Connecting handled above */ }
            }
        }

        // Bottom tab bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant)
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.clickable { selectedTab = 0 },
            ) {
                Icon(
                    ImageVector.vectorResource(R.drawable.ic_wallet),
                    stringResource(R.string.nav_credentials),
                    tint = if (selectedTab == 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.nav_credentials),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (selectedTab == 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.clickable {
                    selectedTab = 1
                    viewModel.openAddCredential()
                },
            ) {
                Icon(
                    Icons.Filled.Add,
                    stringResource(R.string.nav_add),
                    tint = if (selectedTab == 1) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.nav_add),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (selectedTab == 1) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.clickable { selectedTab = 2 },
            ) {
                Icon(
                    Icons.Outlined.Settings,
                    stringResource(R.string.nav_settings),
                    tint = if (selectedTab == 2) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    stringResource(R.string.nav_settings),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (selectedTab == 2) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

// ── Login Screen ────────────────────────────────────────────────────

@Composable
fun LoginScreen(
    backendUrl: String,
    tenantId: String,
    isLoading: Boolean,
    snackbarHostState: SnackbarHostState,
    onBackendUrlChange: (String) -> Unit,
    onTenantIdChange: (String) -> Unit,
    onLogin: () -> Unit,
    onRegister: () -> Unit,
) {
    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 32.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(modifier = Modifier.height(24.dp))
            Image(
                painter = painterResource(R.drawable.ic_siros_mark),
                contentDescription = stringResource(R.string.topbar_logo_description),
                modifier = Modifier.size(56.dp),
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.login_title),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Text(
                text = stringResource(R.string.login_tagline),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(modifier = Modifier.height(20.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedTextField(
                        value = backendUrl,
                        onValueChange = onBackendUrlChange,
                        label = { Text(stringResource(R.string.login_backend_url)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        enabled = !isLoading,
                        shape = RoundedCornerShape(12.dp),
                    )
                    OutlinedTextField(
                        value = tenantId,
                        onValueChange = onTenantIdChange,
                        label = { Text(stringResource(R.string.login_tenant_id)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        enabled = !isLoading,
                        shape = RoundedCornerShape(12.dp),
                    )

                    Spacer(modifier = Modifier.height(4.dp))
                    Button(
                        onClick = onLogin,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        enabled = !isLoading,
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        if (isLoading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = MaterialTheme.colorScheme.onPrimary,
                                strokeWidth = 2.dp,
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text(stringResource(R.string.login_button))
                    }
                    OutlinedButton(
                        onClick = onRegister,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        enabled = !isLoading,
                        shape = RoundedCornerShape(12.dp),
                    ) {
                        Text(stringResource(R.string.login_register_button))
                    }
                }
            }
        }
    }
}

// ── Credentials Tab ─────────────────────────────────────────────────

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun CredentialsTab(
    state: WalletState.Ready,
    onCredentialClick: (org.sirosfoundation.sdk.credentials.StoredCredential) -> Unit,
    onAddCredential: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(
            text = stringResource(R.string.credentials_welcome, state.displayName ?: stringResource(R.string.user_fallback_name)),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = if (state.credentials.size == 1) stringResource(R.string.credentials_count_one, 1)
                   else stringResource(R.string.credentials_count_other, state.credentials.size),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(16.dp))

        if (state.credentials.isEmpty()) {
            EmptyCredentialsCard(onClick = onAddCredential)
        } else if (state.credentials.size == 1) {
            CredentialCard(
                credential = state.credentials.first(),
                onClick = { onCredentialClick(state.credentials.first()) },
            )
        } else {
            // Horizontal pager for swiping between credential cards
            val pagerState = rememberPagerState(pageCount = { state.credentials.size })
            HorizontalPager(
                state = pagerState,
                contentPadding = PaddingValues(end = 32.dp),
                pageSpacing = 12.dp,
            ) { page ->
                val credential = state.credentials[page]
                CredentialCard(
                    credential = credential,
                    onClick = { onCredentialClick(credential) },
                )
            }
            // Page indicator dots
            if (state.credentials.size > 1) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    repeat(state.credentials.size) { index ->
                        Box(
                            modifier = Modifier
                                .padding(horizontal = 4.dp)
                                .size(if (pagerState.currentPage == index) 8.dp else 6.dp)
                                .clip(CircleShape)
                                .background(
                                    if (pagerState.currentPage == index)
                                        MaterialTheme.colorScheme.primary
                                    else
                                        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)
                                ),
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun EmptyCredentialsCard(onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                imageVector = Icons.Filled.Add,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.credentials_empty_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Medium,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.credentials_empty_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

// ── Settings Tab ────────────────────────────────────────────────────

@Composable
fun SettingsTab(
    state: WalletState.Ready,
    backendUrl: String,
    tenantId: String,
    presentationCount: Int,
    lifecycleState: LifecycleState?,
    enrollmentInProgress: Boolean,
    onDisconnect: () -> Unit,
    onShowHistory: () -> Unit,
    onEnrollWscd: () -> Unit,
    onShowWscaDeveloper: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(modifier = Modifier.height(24.dp))

        // Account section
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text(
                    text = stringResource(R.string.settings_account_section),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(modifier = Modifier.height(12.dp))
                SettingsRow(stringResource(R.string.settings_signed_in_as), state.displayName ?: state.userId)
                SettingsRow(stringResource(R.string.settings_backend_url), backendUrl)
                SettingsRow(stringResource(R.string.settings_tenant_id), tenantId)
                SettingsRow(stringResource(R.string.settings_credentials_stored), state.credentials.size.toString())
                SettingsRow(stringResource(R.string.settings_app_version), BuildConfig.VERSION_NAME)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Presentation history link
        OutlinedButton(
            onClick = onShowHistory,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.settings_presentation_history) + " ($presentationCount)")
        }

        Spacer(modifier = Modifier.height(32.dp))

        // WSCD Lifecycle
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "WSCD Lifecycle",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(modifier = Modifier.height(8.dp))
                SettingsRow(
                    label = "State",
                    value = lifecycleState?.name ?: "Not enrolled",
                )
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onEnrollWscd,
                    enabled = !enrollmentInProgress && lifecycleState == null,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    if (enrollmentInProgress) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Text("Enroll WSCD")
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onShowWscaDeveloper,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("WSCA Developer")
                }
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        // Logout
        OutlinedButton(
            onClick = onDisconnect,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.settings_logout))
        }
        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun SettingsRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.primary,
        )
    }
}

// ── Flow Active View ────────────────────────────────────────────────

@Composable
fun FlowActiveView(state: WalletState.FlowActive, onCancel: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        CircularProgressIndicator(modifier = Modifier.size(48.dp), color = MaterialTheme.colorScheme.primary)
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = when (state.flowType) {
                "issuance" -> stringResource(R.string.flow_issuing)
                "presentation" -> stringResource(R.string.flow_presenting)
                else -> stringResource(R.string.flow_processing)
            },
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = state.status,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(32.dp))
        OutlinedButton(
            onClick = onCancel,
            shape = RoundedCornerShape(12.dp),
        ) {
            Text(stringResource(R.string.flow_cancel))
        }
    }
}

// ── Error View ──────────────────────────────────────────────────────

@Composable
fun ErrorView(message: String, onRetry: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = stringResource(R.string.error_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Medium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onRetry, shape = RoundedCornerShape(12.dp)) {
            Text(stringResource(R.string.error_retry))
        }
    }
}
