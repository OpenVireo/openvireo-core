# Applied to apps that depend on openvireo-core-android when they shrink with R8/ProGuard.
#
# JNA finds native methods, Structure fields and Callback methods by reflection, and the generated
# binding (com.openvireo.core) declares its native interface, Structures (@FieldOrder) and callback
# vtables as such classes. Renaming or removing any of them breaks loading at runtime.

# JNA (as JNA's own Android notes ask).
-dontwarn java.awt.**
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-keep class * implements com.sun.jna.** { *; }

# The UniFFI binding: its JNA interface, Structures, callbacks and the classes they name.
-keep class com.openvireo.core.** { *; }
