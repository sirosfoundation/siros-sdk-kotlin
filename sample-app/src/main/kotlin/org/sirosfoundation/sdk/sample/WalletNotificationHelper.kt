// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.sirosfoundation.sdk.sample

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Helper for showing platform-native notifications for credential lifecycle events.
 */
class WalletNotificationHelper(private val context: Context) {

    companion object {
        private const val CHANNEL_ID = "siros_credential_events"
        private const val CHANNEL_NAME = "Credential Events"
        private const val CHANNEL_DESCRIPTION = "Notifications for credential issuance and deletion"
        private var notificationId = 0
    }

    init {
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            CHANNEL_NAME,
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = CHANNEL_DESCRIPTION
        }
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(channel)
    }

    /** Show a notification that a credential was received. */
    fun notifyCredentialReceived(credentialName: String?) {
        val title = "Credential Received"
        val text = credentialName?.let { "\"$it\" has been added to your wallet" }
            ?: "A new credential has been added to your wallet"
        showNotification(title, text)
    }

    /** Show a notification that a credential was deleted. */
    fun notifyCredentialDeleted(credentialName: String?) {
        val title = "Credential Deleted"
        val text = credentialName?.let { "\"$it\" has been removed from your wallet" }
            ?: "A credential has been removed from your wallet"
        showNotification(title, text)
    }

    private fun showNotification(title: String, text: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(context).notify(notificationId++, notification)
    }
}
