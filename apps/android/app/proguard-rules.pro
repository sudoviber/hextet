# hextet Android — R8/ProGuard rules.
#
# Keep the UniFFI generated bindings untouched: they use JNA + reflection-adjacent
# `Native.register` and Structure field ordering, which R8 can otherwise strip/renumber.
# The debug build does not minify; these rules are here for a future release build.
-keep class uniffi.** { *; }
-keep class com.sun.jna.** { *; }
-dontwarn java.awt.**
-dontwarn com.sun.jna.**
