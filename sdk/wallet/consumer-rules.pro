# SIROS SDK — wallet module consumer rules
# Keep public API classes that integrators reference
-keep class org.sirosfoundation.sdk.wallet.SirosWallet { *; }
-keep class org.sirosfoundation.sdk.wallet.SirosWallet$Companion { *; }
-keep class org.sirosfoundation.sdk.wallet.WalletConfig { *; }
-keep class org.sirosfoundation.sdk.wallet.WalletState { *; }
-keep class org.sirosfoundation.sdk.wallet.WalletState$* { *; }
-keep class org.sirosfoundation.sdk.wallet.WalletEventListener { *; }
-keep class org.sirosfoundation.sdk.wallet.WalletException { *; }

# Keep all @Serializable data classes (required by kotlinx.serialization)
-keepclassmembers class org.sirosfoundation.sdk.** {
    *** Companion;
}
-keep class org.sirosfoundation.sdk.**$$serializer { *; }
-keepclassmembers class org.sirosfoundation.sdk.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep kotlinx.serialization infrastructure
-keepattributes *Annotation*
-keep class kotlinx.serialization.** { *; }
