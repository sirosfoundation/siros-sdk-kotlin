# sdk:passkey-provider — keep credential provider service and store
-keep class org.siros.sdk.passkey.SirosCredentialProviderService { *; }
-keep class org.siros.sdk.passkey.PasskeyStore { *; }
-keep class org.siros.sdk.passkey.PasskeyEntry { *; }
-keep class org.siros.sdk.passkey.SharedPrefsPasskeyStore { *; }
# Keep serialization
-keepclassmembers class org.siros.sdk.passkey.** {
    kotlinx.serialization.KSerializer serializer(...);
}
