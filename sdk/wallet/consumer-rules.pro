# SIROS SDK — wallet module consumer rules
# Keep public API classes that integrators reference
-keep class org.siros.sdk.wallet.SirosWallet { *; }
-keep class org.siros.sdk.wallet.SirosWallet$Companion { *; }
-keep class org.siros.sdk.wallet.WalletConfig { *; }
-keep class org.siros.sdk.wallet.WalletState { *; }
-keep class org.siros.sdk.wallet.WalletState$* { *; }
-keep class org.siros.sdk.wallet.WalletEventListener { *; }
-keep class org.siros.sdk.wallet.WalletException { *; }

# Keep all @Serializable data classes (required by kotlinx.serialization)
-keepclassmembers class org.siros.sdk.** {
    *** Companion;
}
-keep class org.siros.sdk.**$$serializer { *; }
-keepclassmembers class org.siros.sdk.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep kotlinx.serialization infrastructure
-keepattributes *Annotation*
-keep class kotlinx.serialization.** { *; }
