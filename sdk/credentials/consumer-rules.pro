# sdk:credentials — keep public types
-keep class org.sirosfoundation.sdk.credentials.CredentialStore { *; }
-keep class org.sirosfoundation.sdk.credentials.StoredCredential { *; }
-keep class org.sirosfoundation.sdk.credentials.CredentialMetadata { *; }
-keep class org.sirosfoundation.sdk.credentials.CredentialOffer { *; }
-keep class org.sirosfoundation.sdk.credentials.CredentialMatcher { *; }
-keep class org.sirosfoundation.sdk.credentials.PresentationRecord { *; }
-keep class org.sirosfoundation.sdk.credentials.SirosException { *; }
-keep class org.sirosfoundation.sdk.credentials.AuthException { *; }
-keep class org.sirosfoundation.sdk.credentials.BackendApiException { *; }
-keep class org.sirosfoundation.sdk.credentials.KeystoreException { *; }
-keep class org.sirosfoundation.sdk.credentials.WalletException { *; }
-keep class org.sirosfoundation.sdk.credentials.NetworkException { *; }
-keep class org.sirosfoundation.sdk.credentials.IssuerEntry { *; }
-keep class org.sirosfoundation.sdk.credentials.IssuerMetadata { *; }
-keep class org.sirosfoundation.sdk.credentials.ClaimMeta { *; }
-keep class org.sirosfoundation.sdk.credentials.IssuerInfo { *; }
-keep class org.sirosfoundation.sdk.credentials.LogoInfo { *; }
-keep class org.sirosfoundation.sdk.credentials.Vctm { *; }
-keep class org.sirosfoundation.sdk.credentials.VctmDisplay { *; }
-keep class org.sirosfoundation.sdk.credentials.VctmClaim { *; }
-keep class org.sirosfoundation.sdk.credentials.VctmFetcher { *; }
# Keep serialization
-keepclassmembers class org.sirosfoundation.sdk.credentials.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep class org.sirosfoundation.sdk.credentials.**$$serializer { *; }
