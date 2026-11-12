# JNI_OnLoad registers NativeRasp.scan by class and method name (RegisterNatives, S2 §7.5).
-keep class org.wolpmessenger.devicetrust.rasp.NativeRasp {
    native <methods>;
}

# libsignal's native code reaches Java classes, constructors and store callbacks by name. Its own rules
# (META-INF/proguard/libsignal.pro) are applied, yet in the R8 release build of 2026-11-12 a session
# between two phones could not be built ("bad_passport" from SessionBuilder.process) while the same
# keys worked on the JVM. Until the cause is pinned down, nothing of libsignal is renamed or removed.
-keep class org.signal.libsignal.** { *; }
-keep interface org.signal.libsignal.** { *; }
-keep enum org.signal.libsignal.** { *; }
