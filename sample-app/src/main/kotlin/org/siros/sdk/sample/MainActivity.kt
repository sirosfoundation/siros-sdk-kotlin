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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    WalletScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(viewModel: WalletViewModel = viewModel()) {
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
                        onBackendUrlChange = viewModel::updateBackendUrl,
                        onConnect = viewModel::connect,
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
                        onLogin = viewModel::login,
                        onRegister = viewModel::register,
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
    onBackendUrlChange: (String) -> Unit,
    onConnect: () -> Unit,
) {
    OutlinedTextField(
        value = backendUrl,
        onValueChange = onBackendUrlChange,
        label = { Text("Backend URL") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
    )
    Button(
        onClick = onConnect,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("Connect")
    }
}

@Composable
fun ConnectedView(
    state: WalletUiState.Connected,
    onLogin: () -> Unit,
    onRegister: () -> Unit,
    onStartIssuance: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    if (!state.isAuthenticated) {
        Button(onClick = onLogin, modifier = Modifier.fillMaxWidth()) {
            Text("Login with Passkey")
        }
        Button(onClick = onRegister, modifier = Modifier.fillMaxWidth()) {
            Text("Register")
        }
    } else {
        Text(
            text = "Logged in as ${state.displayName ?: state.userId}",
            style = MaterialTheme.typography.titleMedium,
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text("Credentials", style = MaterialTheme.typography.titleSmall)

        if (state.credentials.isEmpty()) {
            Text(
                text = "No credentials yet",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                items(state.credentials) { credential ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                text = credential.metadata?.name ?: credential.id,
                                style = MaterialTheme.typography.bodyLarge,
                            )
                            Text(
                                text = credential.format,
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        Button(
            onClick = { onStartIssuance("") },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Accept Credential Offer")
        }
    }

    Spacer(modifier = Modifier.height(16.dp))

    Button(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) {
        Text("Disconnect")
    }
}
