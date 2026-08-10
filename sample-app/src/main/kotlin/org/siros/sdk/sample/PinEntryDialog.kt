// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.sample

import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation

/**
 * Shown when [WalletViewModel]'s `requestFido2Pin` bridge fires - the
 * WSCD asking for the authenticator's real CTAP2 ClientPin PIN (see
 * [PendingPinEntry]'s doc comment). Enter it wrong too many times and
 * the authenticator enforces its own retry lockout (`CTAP2_ERR_PIN_INVALID`,
 * then a transient `CTAP2_ERR_PIN_AUTH_BLOCKED` clearable only by a power
 * cycle) - this dialog has no way to know the correct PIN in advance, so
 * it can't guard against that itself.
 *
 * CTAP2 PINs aren't necessarily numeric (FIDO2 allows any UTF-8 PIN), so
 * this uses a general password keyboard rather than a numeric one.
 */
@Composable
fun PinEntryDialog(pending: PendingPinEntry, onSubmit: (String?) -> Unit) {
    var pin by remember(pending) { mutableStateOf("") }
    val focusRequester = remember(pending) { FocusRequester() }

    LaunchedEffect(pending) { focusRequester.requestFocus() }

    AlertDialog(
        onDismissRequest = { onSubmit(null) },
        title = { Text("Enter security key PIN") },
        text = {
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = it },
                label = { Text("PIN") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = androidx.compose.ui.Modifier.focusRequester(focusRequester),
            )
        },
        confirmButton = {
            Button(onClick = { onSubmit(pin) }, enabled = pin.isNotEmpty()) { Text("Submit") }
        },
        dismissButton = {
            TextButton(onClick = { onSubmit(null) }) { Text("Cancel") }
        },
    )
}
