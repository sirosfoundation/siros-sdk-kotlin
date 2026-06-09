# sdk:auth — keep public API interfaces and data classes
-keep class org.sirosfoundation.sdk.auth.AuthProvider { *; }
-keep class org.sirosfoundation.sdk.auth.AuthSession { *; }
-keep class org.sirosfoundation.sdk.auth.PrfOutput { *; }
# Keep serialization infrastructure
-keepclassmembers class org.sirosfoundation.sdk.auth.** {
    kotlinx.serialization.KSerializer serializer(...);
}
