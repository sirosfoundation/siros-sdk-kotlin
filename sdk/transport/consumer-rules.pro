# sdk:transport — keep engine session and message types
-keep class org.sirosfoundation.sdk.transport.engine.WalletEngineSession { *; }
-keep class org.sirosfoundation.sdk.transport.engine.WalletEngineSession$State { *; }
-keep class org.sirosfoundation.sdk.transport.engine.ProofObject { *; }
-keep class org.sirosfoundation.sdk.transport.engine.CredentialMatch { *; }
# Keep serialization
-keepclassmembers class org.sirosfoundation.sdk.transport.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep class org.sirosfoundation.sdk.transport.**$$serializer { *; }
