# sdk:passkey-provider — keep credential provider service and store
-keep class org.sirosfoundation.sdk.passkey.SirosCredentialProviderService { *; }
-keep class org.sirosfoundation.sdk.passkey.PasskeyStore { *; }
-keep class org.sirosfoundation.sdk.passkey.PasskeyEntry { *; }
-keep class org.sirosfoundation.sdk.passkey.SharedPrefsPasskeyStore { *; }
# Keep serialization
-keepclassmembers class org.sirosfoundation.sdk.passkey.** {
    kotlinx.serialization.KSerializer serializer(...);
}
