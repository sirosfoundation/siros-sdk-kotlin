# sdk:verifier — keep the public trust and proximity engagement types
-keep class org.siros.sdk.verifier.trust.AuthZenPdp { *; }
-keep class org.siros.sdk.verifier.trust.HttpAuthZenPdp { *; }
-keep class org.siros.sdk.verifier.mdoc.proximity.MdocQrEngagement { *; }
-keep class org.siros.sdk.verifier.mdoc.proximity.BleDeviceRetrievalMethod { *; }
# Keep serialization infrastructure
-keepclassmembers class org.siros.sdk.verifier.** {
    kotlinx.serialization.KSerializer serializer(...);
}
# UniFFI/JNA native reader bindings
-keep class uniffi.siros_verifier_core_ffi.** { *; }
-keep class com.sun.jna.** { *; }
-keepclasseswithmembers,includedescriptorclasses class * {
    native <methods>;
}
