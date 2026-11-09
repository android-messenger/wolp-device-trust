# JNI_OnLoad registers NativeRasp.scan by class and method name (RegisterNatives, S2 §7.5).
-keep class org.wolpmessenger.devicetrust.rasp.NativeRasp {
    native <methods>;
}
