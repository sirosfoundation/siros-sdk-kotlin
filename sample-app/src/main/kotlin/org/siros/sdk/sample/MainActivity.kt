package org.siros.sdk.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import org.siros.sdk.wallet.WalletState

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val vmFactory = WalletViewModel.Factory(this)
        setContent {
            SirosTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    WalletScreen(viewModel(factory = vmFactory))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(viewModel: WalletViewModel) {
    val walletState by viewModel.state.collectAsState()
    val backendUrl by viewModel.backendUrl.collectAsState()
    val tenantId by viewModel.tenantId.collectAsState()
    val showAddCredential by viewModel.showAddCredential.collectAsState()
    val availableCredentials by viewModel.availableCredentials.collectAsState()
    val isLoadingOffers by viewModel.isLoadingOffers.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    val errorMessage by viewModel.errorMessage.collectAsState()

    LaunchedEffect(errorMessage) {
        errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearError()
        }
    }

    if (showAddCredential) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Add Credential") },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    ),
                    navigationIcon = {
                        IconButton(onClick = viewModel::closeAddCredential) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
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

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(
                            painter = painterResource(R.drawable.ic_siros_mark),
                            contentDescription = "SIROS",
                            modifier = Modifier.size(32.dp),
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text("SIROS Wallet")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            )
        },
        floatingActionButton = {
            if (walletState is WalletState.Ready) {
                FloatingActionButton(
                    onClick = viewModel::openAddCredential,
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                ) {
                    Icon(Icons.Filled.Add, "Add Credential")
                }
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (val state = walletState) {
                is WalletState.Disconnected -> {
                    NotConnectedView(
                        backendUrl = backendUrl,
                        tenantId = tenantId,
                        isLoading = isLoading,
                        onBackendUrlChange = viewModel::updateBackendUrl,
                        onTenantIdChange = viewModel::updateTenantId,
                        onLogin = viewModel::login,
                        onRegister = viewModel::register,
                    )
                }
                is WalletState.Connecting -> {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("Connecting...")
                    }
                }
                is WalletState.Ready -> {
                    ReadyView(
                        state = state,
                        onDisconnect = viewModel::disconnect,
                    )
                }
                is WalletState.FlowActive -> {
                    Column {
                        Text(
                            text = "Flow in progress: ${state.flowType}",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Status: ${state.status}")
                    }
                }
                is WalletState.Error -> {
                    Text(
                        text = "Error: ${state.message}",
                        color = MaterialTheme.colorScheme.error,
                    )
                    Button(onClick = viewModel::disconnect) {
                        Text("Retry")
                    }
                }
            }
        }
    }
}

@Composable
fun NotConnectedView(
    backendUrl: String,
    tenantId: String,
    isLoading: Boolean,
    onBackendUrlChange: (String) -> Unit,
    onTenantIdChange: (String) -> Unit,
    onLogin: () -> Unit,
    onRegister: () -> Unit,
) {
    OutlinedTextField(
        value = backendUrl,
        onValueChange = onBackendUrlChange,
        label = { Text("Backend URL") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        enabled = !isLoading,
    )
    OutlinedTextField(
        value = tenantId,
        onValueChange = onTenantIdChange,
        label = { Text("Tenant ID") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        enabled = !isLoading,
    )

    Spacer(modifier = Modifier.height(8.dp))

    Button(
        onClick = onLogin,
        modifier = Modifier.fillMaxWidth(),
        enabled = !isLoading,
    ) {
        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                color = MaterialTheme.colorScheme.onPrimary,
                strokeWidth = 2.dp,
            )
            Spacer(modifier = Modifier.width(8.dp))
        }
        Text("Login with Passkey")
    }
    OutlinedButton(
        onClick = onRegister,
        modifier = Modifier.fillMaxWidth(),
        enabled = !isLoading,
    ) {
        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                color = MaterialTheme.colorScheme.primary,
                strokeWidth = 2.dp,
            )
            Spacer(modifier = Modifier.width(8.dp))
        }
        Text("Register")
    }
}

@Composable
fun ReadyView(
    state: WalletState.Ready,
    onDisconnect: () -> Unit,
) {
    Text(
        text = "Logged in as ${state.displayName ?: state.userId}",
        style = MaterialTheme.typography.titleMedium,
    )

    if (state.credentials.isEmpty()) {
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "No credentials yet. Tap + to add one.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    } else {
        Text(
            text = "${state.credentials.size} credential(s)",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(8.dp))
        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.heightIn(max = 400.dp),
        ) {
            items(state.credentials) { credential ->
                CredentialCard(credential = credential)
            }
        }
    }

    Spacer(modifier = Modifier.height(16.dp))

    OutlinedButton(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) {
        Text("Disconnect")
    }
}
