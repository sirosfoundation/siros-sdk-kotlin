# sdk:keystore — keep public interface and data types
-keep class org.siros.sdk.keystore.KeystoreManager { *; }
-keep class org.siros.sdk.keystore.KeyInfo { *; }

# JNA — required by UniFFI-generated bindings (siros-wscd-manager).
# JNA accesses these fields via JNI; R8 must not strip or rename them.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.Library { *; }
-keep class * implements com.sun.jna.Callback { *; }
-keepclassmembers class * extends com.sun.jna.Structure { public *; }

# UniFFI generated bindings
-keep class uniffi.** { *; }
