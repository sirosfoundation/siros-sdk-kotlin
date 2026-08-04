package org.siros.sdk.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Switch
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
import androidx.compose.runtime.mutableStateOf
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
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.keystore.DestroyMode
import org.siros.sdk.keystore.LifecycleState
import org.siros.sdk.wallet.WalletState
import android.util.Log
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import org.siros.sdk.wallet.DeepLinkType
import org.siros.sdk.wallet.classifyDeepLink

class MainActivity : ComponentActivity() {
    private lateinit var viewModel: WalletViewModel
    private val tag = "SIROS_MAIN"
    private var pendingWscaIntent: android.content.Intent? = null

    /**
     * Copies backend_url/tenant_id/engine_url string extras from the launch
     * intent into the "siros_test_overrides" prefs store WalletViewModel
     * reads at construction time - e.g.:
     *   adb shell am start -n org.siros.sdk.sample/.MainActivity \
     *     --es backend_url "https://sirosid-<env>-wallet-proxy.fly.dev" \
     *     --es tenant_id "default"
     * Debug builds only (matches the existing ACTION_WSCA_TEST precedent) -
     * an exported activity honoring these in a release build would let any
     * app on the device silently redirect a real wallet's backend URL.
     * Must run before the ViewModel is constructed (i.e. before setContent),
     * since it only reads these prefs once, in its init block.
     */
    private fun applyIntentTestOverrides(intent: android.content.Intent?) {
        if (!BuildConfig.DEBUG || intent == null) return
        val backendUrl = intent.getStringExtra("backend_url")
        val tenantId = intent.getStringExtra("tenant_id")
        val engineUrl = intent.getStringExtra("engine_url")
        if (backendUrl == null && tenantId == null && engineUrl == null) return
        getSharedPreferences("siros_test_overrides", MODE_PRIVATE).edit().apply {
            backendUrl?.let { putString("backend_url", it) }
            tenantId?.let { putString("tenant_id", it) }
            engineUrl?.let { putString("engine_url", it) }
        }.apply()
    }

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
        // Must run before WalletViewModel.Factory constructs the ViewModel -
        // it only reads siros_test_overrides prefs once, in its init block.
        applyIntentTestOverrides(intent)
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
     *   adb shell am start -n $PKG/.MainActivity -a org.siros.sdk.sample.WSCA_TEST \
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
        internal const val ACTION_WSCA_TEST = "org.siros.sdk.sample.WSCA_TEST"
        internal const val WSCA_TEST_TAG = "WSCA_TEST_RESULT"
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(viewModel: WalletViewModel) {
    val walletState by viewModel.state.collectAsState()
    val r2psServerUrl by viewModel.r2psServerUrl.collectAsState()
    val showAddCredential by viewModel.showAddCredential.collectAsState()
    val availableCredentials by viewModel.availableCredentials.collectAsState()
    val isLoadingOffers by viewModel.isLoadingOffers.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val errorMessage by viewModel.errorMessage.collectAsState()
    val infoMessage by viewModel.infoMessage.collectAsState()
    val flowErrorDialog by viewModel.flowErrorDialog.collectAsState()
    val presentationHistory by viewModel.presentationHistory.collectAsState()
    val selectedCredential by viewModel.selectedCredential.collectAsState()
    val showHistory by viewModel.showHistory.collectAsState()
    val showQrScanner by viewModel.showQrScanner.collectAsState()
    val showProximityEngagement by viewModel.showProximityEngagement.collectAsState()
    val pendingPresentation by viewModel.pendingPresentationRequest.collectAsState()
    val useWmpProtocol by viewModel.useWmpProtocol.collectAsState()
    val showCredentialDetails by viewModel.showCredentialDetails.collectAsState()

    LaunchedEffect(errorMessage) {
        errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearError()
        }
    }

    LaunchedEffect(infoMessage) {
        infoMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearInfo()
        }
    }

    // Terminal flow failure (e.g. untrusted issuer) - unlike the Snackbar above,
    // this needs an explicit user decision rather than an auto-dismissing toast,
    // since the flow itself is already over and won't resume on its own.
    flowErrorDialog?.let { info ->
        androidx.compose.material3.AlertDialog(
            onDismissRequest = viewModel::dismissFlowError,
            title = { Text(stringResource(R.string.flow_error_title)) },
            text = { Text(info.message) },
            confirmButton = {
                TextButton(onClick = viewModel::retryLastFlow, enabled = info.canRetry) {
                    Text(stringResource(R.string.error_retry))
                }
            },
            dismissButton = {
                TextButton(onClick = viewModel::dismissFlowError) {
                    Text(stringResource(R.string.flow_cancel))
                }
            },
        )
    }

    // Not logged in → show login screen (no app chrome)
    if (walletState is WalletState.Disconnected || walletState is WalletState.Connecting) {
        val cachedAccounts = (walletState as? WalletState.Disconnected)?.cachedAccounts ?: emptyList()
        val backendUrlState by viewModel.backendUrl.collectAsState()
        val tenantIdState by viewModel.tenantId.collectAsState()
        val engineUrlOverrideState by viewModel.engineUrlOverride.collectAsState()
        LoginScreen(
            cachedAccounts = cachedAccounts,
            backendUrl = backendUrlState,
            tenantId = tenantIdState,
            engineUrl = engineUrlOverrideState,
            useWmpProtocol = useWmpProtocol,
            showPreLoginSettings = BuildConfig.SHOW_PRE_LOGIN_SETTINGS,
            isLoading = isLoading || walletState is WalletState.Connecting,
            snackbarHostState = snackbarHostState,
            onLogin = viewModel::login,
            onLoginAccount = { account -> viewModel.login(account.accountId) },
            onForgetAccount = viewModel::forgetAccount,
            onRegister = { name -> viewModel.register(name) },
            onUpdateBackendUrl = viewModel::updateBackendUrl,
            onUpdateTenantId = viewModel::updateTenantId,
            onUpdateEngineUrl = viewModel::updateEngineUrl,
            onUpdateUseWmpProtocol = viewModel::updateUseWmpProtocol,
        )
        return
    }

    // Fatal error without a valid session → full-screen error, no navigation chrome.
    // The user must tap "Retry" (which disconnects → back to login).
    if (walletState is WalletState.Error) {
        ErrorView(
            message = (walletState as WalletState.Error).message,
            onRetry = viewModel::disconnect,
        )
        return
    }

    // WSCA developer sub-screen state (read here so it's available in the `when` below)
    val showWscaDeveloper by viewModel.showWscaDeveloper.collectAsState()
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }

    // Everything below shares one Box so the SnackbarHost always has somewhere to
    // render, no matter which sub-screen is active - previously each sub-screen
    // branch `return`ed before ever reaching a SnackbarHost, so post-login errors
    // (e.g. a failed credential issuance) were silently swallowed.
    Box(modifier = Modifier.fillMaxSize()) {
        when {
            // Presentation consent dialog — shown as a full-screen overlay
            pendingPresentation != null -> PresentationConsentScreen(
                request = pendingPresentation!!,
                onAccept = viewModel::acceptPresentation,
                onDecline = viewModel::declinePresentation,
            )

            // Credential detail sub-screen
            selectedCredential != null -> CredentialDetailScreen(
                credential = selectedCredential!!,
                onBack = viewModel::closeCredentialDetail,
                onDelete = { viewModel.deleteCredential(selectedCredential!!.id) },
            )

            // Presentation history sub-screen
            showHistory -> PresentationHistoryScreen(
                history = presentationHistory,
                onBack = viewModel::closeHistory,
            )

            // WSCA developer sub-screen
            showWscaDeveloper -> {
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
            }

            // QR scanner sub-screen
            showQrScanner -> QrScannerScreen(
                onQrScanned = viewModel::handleQrResult,
                onBack = viewModel::closeQrScanner,
            )

            // ISO 18013-5 proximity engagement (QR + NFC + BLE) sub-screen
            showProximityEngagement -> ProximityEngagementScreen(
                getCredentials = viewModel::getCredentialsForProximity,
                signPresentation = viewModel::signMdocPresentationForProximity,
                onBack = viewModel::closeProximityEngagement,
            )

            // Add credential sub-screen
            showAddCredential -> {
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
                    val pendingOffer by viewModel.pendingIssuanceOffer.collectAsState()
                    AddCredentialScreen(
                        offers = availableCredentials,
                        isLoading = isLoadingOffers,
                        onOfferSelected = viewModel::selectCredentialOffer,
                        pendingOffer = pendingOffer,
                        onConfirmIssuance = viewModel::confirmIssuance,
                        onCancelIssuance = viewModel::cancelIssuance,
                        onStartIDV = viewModel::startIDV,
                        onRetry = viewModel::openAddCredential,
                        modifier = Modifier.padding(padding),
                    )
                }
            }

            // Main app with bottom navigation
            else -> Column(modifier = Modifier.fillMaxSize()) {
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
                        2 -> SettingsTab(
                            state = state,
                            backendUrl = viewModel.backendUrl.collectAsState().value,
                            tenantId = viewModel.tenantId.collectAsState().value,
                            useWmpProtocol = useWmpProtocol,
                            presentationCount = presentationHistory.size,
                            lifecycleState = viewModel.lifecycleState.collectAsState().value,
                            enrollmentInProgress = viewModel.enrollmentInProgress.collectAsState().value,
                            onDisconnect = viewModel::disconnect,
                            onDeleteAccount = viewModel::deleteAccount,
                            onShowHistory = viewModel::openHistory,
                            onEnrollWscd = viewModel::enrollWscd,
                            onShowWscaDeveloper = viewModel::openWscaDeveloper,
                            onShowProximityEngagement = viewModel::openProximityEngagement,
                            onForgetAccount = viewModel::forgetAccount,
                            passkeys = viewModel.listPasskeys(),
                            onRenamePasskey = viewModel::renamePasskey,
                            showCredentialDetails = showCredentialDetails,
                            onUpdateShowCredentialDetails = viewModel::updateShowCredentialDetails,
                            showDiagnosticMessages = viewModel.showDiagnosticMessages.collectAsState().value,
                            onUpdateShowDiagnosticMessages = viewModel::updateShowDiagnosticMessages,
                        )
                        // selectedTab can transiently be 1 (the "Add" action, not a
                        // real persisted tab) right as a flow finishes and the state
                        // drops back to Ready - fall through to the credentials list
                        // rather than rendering nothing.
                        else -> CredentialsTab(
                            state = state,
                            presentationHistory = presentationHistory,
                            onCredentialClick = viewModel::openCredentialDetail,
                            onAddCredential = viewModel::openAddCredential,
                        )
                    }
                }
                is WalletState.FlowActive -> {
                    FlowActiveView(
                        state = state,
                        onCancel = viewModel::cancelCurrentFlow,
                        showDiagnosticMessages = viewModel.showDiagnosticMessages.collectAsState().value,
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

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter),
        )
    }
}

// ── Login Screen ────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(
    cachedAccounts: List<org.siros.sdk.wallet.CachedAccount>,
    backendUrl: String,
    tenantId: String,
    engineUrl: String,
    useWmpProtocol: Boolean,
    showPreLoginSettings: Boolean,
    isLoading: Boolean,
    snackbarHostState: SnackbarHostState,
    onLogin: () -> Unit,
    onLoginAccount: (org.siros.sdk.wallet.CachedAccount) -> Unit,
    onForgetAccount: (String) -> Unit,
    onRegister: (String) -> Unit,
    onUpdateBackendUrl: (String) -> Unit,
    onUpdateTenantId: (String) -> Unit,
    onUpdateEngineUrl: (String) -> Unit,
    onUpdateUseWmpProtocol: (Boolean) -> Unit,
) {
    var showRegister by remember { mutableStateOf(false) }
    var showOtherLogin by remember { mutableStateOf(false) }
    var registerName by remember { mutableStateOf("") }
    var showBackendInfo by remember { mutableStateOf(false) }
    var showSettingsSheet by remember { mutableStateOf(false) }

    if (showSettingsSheet) {
        PreLoginSettingsSheet(
            backendUrl = backendUrl,
            tenantId = tenantId,
            engineUrl = engineUrl,
            useWmpProtocol = useWmpProtocol,
            onUpdateBackendUrl = onUpdateBackendUrl,
            onUpdateTenantId = onUpdateTenantId,
            onUpdateEngineUrl = onUpdateEngineUrl,
            onUpdateUseWmpProtocol = onUpdateUseWmpProtocol,
            onDismiss = { showSettingsSheet = false },
        )
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            if (showPreLoginSettings) {
                TopAppBar(
                    title = {},
                    actions = {
                        IconButton(
                            onClick = { showSettingsSheet = true },
                        ) {
                            Icon(
                                Icons.Outlined.Settings,
                                contentDescription = "Settings",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    },
                )
            }
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
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
            )
            // Info icon showing backend URL
            Row(
                modifier = Modifier.clickable { showBackendInfo = !showBackendInfo },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Outlined.Info, contentDescription = "Backend info", modifier = Modifier.size(14.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    if (showBackendInfo) backendUrl else stringResource(R.string.login_tagline),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(modifier = Modifier.height(20.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    when {
                        // Mode C: Registration
                        showRegister -> {
                            Text(stringResource(R.string.login_register_button),
                                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            OutlinedTextField(
                                value = registerName,
                                onValueChange = { if (it.toByteArray().size <= 64) registerName = it },
                                label = { Text("Display name") },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                enabled = !isLoading,
                                shape = RoundedCornerShape(12.dp),
                                supportingText = { Text("${registerName.toByteArray().size}/64") },
                            )
                            Button(
                                onClick = { onRegister(registerName) },
                                modifier = Modifier.fillMaxWidth().height(48.dp),
                                enabled = !isLoading && registerName.isNotBlank(),
                                shape = RoundedCornerShape(12.dp),
                            ) {
                                if (isLoading) {
                                    CircularProgressIndicator(modifier = Modifier.size(20.dp),
                                        color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                                    Spacer(modifier = Modifier.width(8.dp))
                                }
                                Text("Sign up with passkey")
                            }
                            TextButton(onClick = { showRegister = false }) {
                                Text("Already have an account? Login")
                            }
                        }

                        // Mode A: Cached accounts (returning users)
                        cachedAccounts.isNotEmpty() && !showOtherLogin -> {
                            Text("Welcome back",
                                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            cachedAccounts.forEach { account ->
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Button(
                                        onClick = { onLoginAccount(account) },
                                        modifier = Modifier.weight(1f).height(48.dp),
                                        enabled = !isLoading,
                                        shape = RoundedCornerShape(12.dp),
                                    ) {
                                        if (isLoading) {
                                            CircularProgressIndicator(modifier = Modifier.size(20.dp),
                                                color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                                            Spacer(modifier = Modifier.width(8.dp))
                                        }
                                        Text(account.displayName, maxLines = 1)
                                    }
                                    Spacer(modifier = Modifier.width(8.dp))
                                    IconButton(onClick = { onForgetAccount(account.accountId) }) {
                                        Icon(Icons.Default.Close, contentDescription = "Forget account")
                                    }
                                }
                            }
                            TextButton(onClick = { showOtherLogin = true }) {
                                Text("Use other account")
                            }
                        }

                        // Mode B: Generic passkey login
                        else -> {
                            Button(
                                onClick = onLogin,
                                modifier = Modifier.fillMaxWidth().height(48.dp),
                                enabled = !isLoading,
                                shape = RoundedCornerShape(12.dp),
                            ) {
                                if (isLoading) {
                                    CircularProgressIndicator(modifier = Modifier.size(20.dp),
                                        color = MaterialTheme.colorScheme.onPrimary, strokeWidth = 2.dp)
                                    Spacer(modifier = Modifier.width(8.dp))
                                }
                                Text(stringResource(R.string.login_button))
                            }
                            TextButton(onClick = { showRegister = true }) {
                                Text("New here? Sign up")
                            }
                            if (cachedAccounts.isNotEmpty()) {
                                TextButton(onClick = { showOtherLogin = false }) {
                                    Text("Back to saved accounts")
                                }
                            }
                        }
                    }
                }
            } // Column
        } // Box
    } // Scaffold padding
    } // Scaffold
} // LoginScreen

// ── Pre-Login Settings Bottom Sheet ────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PreLoginSettingsSheet(
    backendUrl: String,
    tenantId: String,
    engineUrl: String,
    useWmpProtocol: Boolean,
    onUpdateBackendUrl: (String) -> Unit,
    onUpdateTenantId: (String) -> Unit,
    onUpdateEngineUrl: (String) -> Unit,
    onUpdateUseWmpProtocol: (Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    var editBackendUrl by remember { mutableStateOf(backendUrl) }
    var editTenantId by remember { mutableStateOf(tenantId) }
    var editEngineUrl by remember { mutableStateOf(engineUrl) }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "Connection Settings",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Text(
                "Configure before registering. Changes take effect on next connection.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = editBackendUrl,
                onValueChange = { editBackendUrl = it; onUpdateBackendUrl(it) },
                label = { Text("Backend URL") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = editTenantId,
                onValueChange = { editTenantId = it; onUpdateTenantId(it) },
                label = { Text("Tenant ID") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = editEngineUrl,
                onValueChange = { editEngineUrl = it; onUpdateEngineUrl(it) },
                label = { Text("Engine URL (blank = auto)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            // Transport protocol toggle
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("WMP Protocol", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        if (useWmpProtocol) "JSON-RPC 2.0 (WMP)" else "Legacy engine protocol",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = useWmpProtocol,
                    onCheckedChange = onUpdateUseWmpProtocol,
                )
            }
        }
    }
}

// ── Credentials Tab ─────────────────────────────────────────────────

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun CredentialsTab(
    state: WalletState.Ready,
    presentationHistory: List<org.siros.sdk.credentials.PresentationRecord>,
    onCredentialClick: (org.siros.sdk.credentials.StoredCredential) -> Unit,
    onAddCredential: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // One entry per batch (see StoredCredential.batchId) instead of one per
    // issued copy - mirrors wallet-frontend's fetchVcData grouping so a
    // 5-copy batch issuance shows as a single card with a remaining-copies
    // ribbon, not five swipeable duplicates.
    val grouped = remember(state.credentials, presentationHistory) {
        org.siros.sdk.credentials.CredentialUtils.groupForDisplay(state.credentials, presentationHistory)
    }

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
            text = if (grouped.size == 1) stringResource(R.string.credentials_count_one, 1)
                   else stringResource(R.string.credentials_count_other, grouped.size),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(16.dp))

        if (grouped.isEmpty()) {
            EmptyCredentialsCard(onClick = onAddCredential)
        } else if (grouped.size == 1) {
            val entry = grouped.first()
            CredentialCard(
                credential = entry.credential,
                instances = entry.instances,
                onClick = { onCredentialClick(entry.credential) },
            )
        } else {
            // Horizontal pager for swiping between credential cards
            val pagerState = rememberPagerState(pageCount = { grouped.size })
            HorizontalPager(
                state = pagerState,
                contentPadding = PaddingValues(end = 32.dp),
                pageSpacing = 12.dp,
            ) { page ->
                val entry = grouped[page]
                CredentialCard(
                    credential = entry.credential,
                    instances = entry.instances,
                    onClick = { onCredentialClick(entry.credential) },
                )
            }
            // Page indicator dots
            if (grouped.size > 1) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    repeat(grouped.size) { index ->
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
    useWmpProtocol: Boolean,
    presentationCount: Int,
    lifecycleState: LifecycleState?,
    enrollmentInProgress: Boolean,
    onDisconnect: () -> Unit,
    onDeleteAccount: () -> Unit,
    onShowHistory: () -> Unit,
    onEnrollWscd: () -> Unit,
    onShowWscaDeveloper: () -> Unit,
    onShowProximityEngagement: () -> Unit,
    onForgetAccount: ((String) -> Unit)? = null,
    passkeys: List<org.siros.sdk.wallet.CachedPasskey> = emptyList(),
    onRenamePasskey: ((String, String) -> Unit)? = null,
    onUpdateUseWmpProtocol: ((Boolean) -> Unit)? = null,
    showCredentialDetails: Boolean = false,
    onUpdateShowCredentialDetails: ((Boolean) -> Unit)? = null,
    showDiagnosticMessages: Boolean = true,
    onUpdateShowDiagnosticMessages: ((Boolean) -> Unit)? = null,
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
                SettingsRow("Transport", if (useWmpProtocol) "WMP (JSON-RPC 2.0)" else "Legacy")
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.settings_credential_details),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Text(
                            stringResource(R.string.settings_credential_details_description),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = showCredentialDetails,
                        onCheckedChange = onUpdateShowCredentialDetails,
                        enabled = onUpdateShowCredentialDetails != null,
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.settings_diagnostic_messages),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        Text(
                            stringResource(R.string.settings_diagnostic_messages_description),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = showDiagnosticMessages,
                        onCheckedChange = onUpdateShowDiagnosticMessages,
                        enabled = onUpdateShowDiagnosticMessages != null,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Passkeys section
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        ) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                Text("Passkeys", style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.height(8.dp))
                if (passkeys.isEmpty()) {
                    Text("No passkeys registered", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    passkeys.forEach { passkey ->
                        var editing by remember { mutableStateOf(false) }
                        var nickname by remember { mutableStateOf(passkey.nickname) }
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            if (editing) {
                                OutlinedTextField(
                                    value = nickname,
                                    onValueChange = { nickname = it },
                                    modifier = Modifier.weight(1f),
                                    singleLine = true,
                                    shape = RoundedCornerShape(8.dp),
                                )
                                IconButton(onClick = {
                                    onRenamePasskey?.invoke(passkey.credentialId, nickname)
                                    editing = false
                                }) {
                                    Icon(Icons.Default.Check, contentDescription = "Save",
                                        modifier = Modifier.size(18.dp))
                                }
                                IconButton(onClick = { editing = false; nickname = passkey.nickname }) {
                                    Icon(Icons.Default.Close, contentDescription = "Cancel",
                                        modifier = Modifier.size(18.dp))
                                }
                            } else {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        passkey.nickname.ifEmpty { "Passkey ${passkey.credentialId.take(8)}..." },
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    Text(
                                        "ID: ${passkey.credentialId.take(16)}...",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                IconButton(onClick = { editing = true }) {
                                    Icon(Icons.Default.Edit, contentDescription = "Rename",
                                        modifier = Modifier.size(18.dp))
                                }
                            }
                        }
                    }
                }
            }
        }

        // Other accounts section (if there are cached accounts)
        if (state.cachedAccounts.size > 1) {
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(20.dp)) {
                    Text("Other Accounts", style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(modifier = Modifier.height(8.dp))
                    state.cachedAccounts
                        .filter { it.accountId != "${tenantId}:${state.userId}" }
                        .forEach { account ->
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(account.displayName, modifier = Modifier.weight(1f),
                                    style = MaterialTheme.typography.bodyMedium)
                                Text(account.tenantId, style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                                if (onForgetAccount != null) {
                                    IconButton(onClick = { onForgetAccount(account.accountId) },
                                        modifier = Modifier.size(32.dp)) {
                                        Icon(Icons.Default.Close, contentDescription = "Remove",
                                            modifier = Modifier.size(16.dp))
                                    }
                                }
                            }
                        }
                }
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
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onShowProximityEngagement,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Text("Proximity Engagement (Interop Test)")
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

        // Delete account
        Spacer(modifier = Modifier.height(8.dp))
        var showDeleteConfirm by remember { mutableStateOf(false) }
        OutlinedButton(
            onClick = { showDeleteConfirm = true },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
        ) {
            Text("Delete Account")
        }
        if (showDeleteConfirm) {
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { showDeleteConfirm = false },
                title = { Text("Delete Account?") },
                text = { Text("This will remove all local data, credentials, and passkeys. This cannot be undone.") },
                confirmButton = {
                    TextButton(onClick = {
                        showDeleteConfirm = false
                        onDeleteAccount()
                    }) {
                        Text("Delete", color = MaterialTheme.colorScheme.error)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showDeleteConfirm = false }) {
                        Text("Cancel")
                    }
                },
            )
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
fun FlowActiveView(
    state: WalletState.FlowActive,
    onCancel: () -> Unit,
    showDiagnosticMessages: Boolean = true,
    modifier: Modifier = Modifier,
) {
    val stepProgress = flowStepProgress(state.flowType, state.status)

    // Guard against a visible backward jump: real execution order can
    // deviate slightly from the canonical step list (e.g. a step retried
    // after a transient error), but the bar should never un-progress.
    var maxProgress by remember(state.flowId) { mutableStateOf(0f) }
    LaunchedEffect(stepProgress) {
        stepProgress?.let { maxProgress = maxOf(maxProgress, it) }
    }

    Column(
        modifier = modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        if (stepProgress != null) {
            LinearProgressIndicator(
                progress = { maxProgress },
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.primary,
            )
        } else {
            LinearProgressIndicator(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.primary,
            )
        }
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
            text = stringResource(flowStepLabelRes(state.status)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (showDiagnosticMessages) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.flow_diagnostic_label, state.status),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            )
        }
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
