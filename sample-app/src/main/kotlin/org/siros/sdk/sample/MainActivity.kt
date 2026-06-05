package org.siros.sdk.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val vmFactory = WalletViewModel.Factory(this)
        setContent {
            MaterialTheme {
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
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("SIROS SDK Sample") })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (val state = uiState) {
                is WalletUiState.NotConnected -> {
                    NotConnectedView(
                        backendUrl = state.backendUrl,
                        tenantId = state.tenantId,
                        onBackendUrlChange = viewModel::updateBackendUrl,
                        onTenantIdChange = viewModel::updateTenantId,
                        onLogin = viewModel::login,
                        onRegister = viewModel::register,
                    )
                }
                is WalletUiState.Connecting -> {
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
                is WalletUiState.Connected -> {
                    ConnectedView(
                        state = state,
                        onStartIssuance = viewModel::startIssuance,
                        onDisconnect = viewModel::disconnect,
                    )
                }
                is WalletUiState.Error -> {
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
    )
    OutlinedTextField(
        value = tenantId,
        onValueChange = onTenantIdChange,
        label = { Text("Tenant ID") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
    )

    Spacer(modifier = Modifier.height(8.dp))

    Button(onClick = onLogin, modifier = Modifier.fillMaxWidth()) {
        Text("Login with Passkey")
    }
    Button(onClick = onRegister, modifier = Modifier.fillMaxWidth()) {
        Text("Register")
    }
}

@Composable
fun ConnectedView(
    state: WalletUiState.Connected,
    onStartIssuance: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    Text(
        text = "Logged in as ${state.displayName ?: state.userId}",
        style = MaterialTheme.typography.titleMedium,
    )

    state.flowStatus?.let { status ->
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Flow: $status",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    Spacer(modifier = Modifier.height(8.dp))

    Button(
        onClick = { onStartIssuance("") },
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("Accept Credential Offer")
    }

    Spacer(modifier = Modifier.height(16.dp))

    Button(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) {
        Text("Disconnect")
    }
}
