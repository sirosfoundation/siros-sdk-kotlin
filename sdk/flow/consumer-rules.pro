# sdk:flow — keep public types
-keep class org.siros.sdk.flow.FlowClient { *; }
-keep class org.siros.sdk.flow.FlowMessage { *; }
# Keep serialization
-keepclassmembers class org.siros.sdk.flow.** {
    kotlinx.serialization.KSerializer serializer(...);
}
