# sdk:flow — keep public types
-keep class org.sirosfoundation.sdk.flow.FlowClient { *; }
-keep class org.sirosfoundation.sdk.flow.FlowMessage { *; }
# Keep serialization
-keepclassmembers class org.sirosfoundation.sdk.flow.** {
    kotlinx.serialization.KSerializer serializer(...);
}
