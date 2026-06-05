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
import org.siros.sdk.wallet.WalletState

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
    val walletState by viewModel.state.collectAsState()
    val backendUrl by viewModel.backendUrl.collectAsState()
    val tenantId by viewModel.tenantId.collectAsState()

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
            when (val state = walletState) {
                is WalletState.Disconnected -> {
                    NotConnectedView(
                        backendUrl = backendUrl,
                        tenantId = tenantId,
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
                        onStartIssuance = viewModel::startIssuance,
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
fun ReadyView(
    state: WalletState.Ready,
    onStartIssuance: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    Text(
        text = "Logged in as ${state.displayName ?: state.userId}",
        style = MaterialTheme.typography.titleMedium,
    )

    if (state.credentials.isNotEmpty()) {
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "${state.credentials.size} credential(s)",
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
