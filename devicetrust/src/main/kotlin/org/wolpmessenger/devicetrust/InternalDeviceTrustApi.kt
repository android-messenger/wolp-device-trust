package org.wolpmessenger.devicetrust

/**
 * Building blocks below the public facade (S2 §4). The application must use only the
 * `DeviceTrust` facade; these are public solely for the library's own modules
 * (`sample`) and require an explicit opt-in.
 */
@RequiresOptIn(
    message = "Internal device-trust building block. Applications must use the DeviceTrust facade (S2 §4).",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY, AnnotationTarget.CONSTRUCTOR)
public annotation class InternalDeviceTrustApi
