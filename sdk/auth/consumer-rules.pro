# sdk:auth — keep public API interfaces and data classes
-keep class org.siros.sdk.auth.AuthProvider { *; }
-keep class org.siros.sdk.auth.AuthSession { *; }
-keep class org.siros.sdk.auth.PrfOutput { *; }
# Keep serialization infrastructure
-keepclassmembers class org.siros.sdk.auth.** {
    kotlinx.serialization.KSerializer serializer(...);
}
