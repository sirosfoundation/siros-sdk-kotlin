# sdk:credentials — keep public types
-keep class org.siros.sdk.credentials.CredentialStore { *; }
-keep class org.siros.sdk.credentials.StoredCredential { *; }
-keep class org.siros.sdk.credentials.CredentialMetadata { *; }
-keep class org.siros.sdk.credentials.CredentialOffer { *; }
-keep class org.siros.sdk.credentials.CredentialMatcher { *; }
-keep class org.siros.sdk.credentials.PresentationRecord { *; }
-keep class org.siros.sdk.credentials.SirosException { *; }
-keep class org.siros.sdk.credentials.AuthException { *; }
-keep class org.siros.sdk.credentials.BackendApiException { *; }
-keep class org.siros.sdk.credentials.KeystoreException { *; }
-keep class org.siros.sdk.credentials.WalletException { *; }
-keep class org.siros.sdk.credentials.NetworkException { *; }
-keep class org.siros.sdk.credentials.IssuerEntry { *; }
-keep class org.siros.sdk.credentials.IssuerMetadata { *; }
-keep class org.siros.sdk.credentials.ClaimMeta { *; }
-keep class org.siros.sdk.credentials.IssuerInfo { *; }
-keep class org.siros.sdk.credentials.LogoInfo { *; }
-keep class org.siros.sdk.credentials.Vctm { *; }
-keep class org.siros.sdk.credentials.VctmDisplay { *; }
-keep class org.siros.sdk.credentials.VctmClaim { *; }
-keep class org.siros.sdk.credentials.VctmFetcher { *; }
# Keep serialization
-keepclassmembers class org.siros.sdk.credentials.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep class org.siros.sdk.credentials.**$$serializer { *; }
