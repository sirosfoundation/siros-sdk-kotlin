# sdk:transport — keep engine session and message types
-keep class org.siros.sdk.transport.engine.WalletEngineSession { *; }
-keep class org.siros.sdk.transport.engine.WalletEngineSession$State { *; }
-keep class org.siros.sdk.transport.engine.ProofObject { *; }
-keep class org.siros.sdk.transport.engine.CredentialMatch { *; }
# Keep serialization
-keepclassmembers class org.siros.sdk.transport.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep class org.siros.sdk.transport.**$$serializer { *; }
