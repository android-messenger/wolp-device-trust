package org.wolpmessenger.devicetrust

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.wolpmessenger.devicetrust.api.VaultException
import org.wolpmessenger.devicetrust.api.VaultPurpose
import org.wolpmessenger.devicetrust.vault.EnvelopeVault
import org.wolpmessenger.devicetrust.vault.VaultKeys

/** Vault over the real Keystore KEK (S2 §9). Measurements: sample app / tools/bench.sh. */
@RunWith(AndroidJUnit4::class)
class VaultDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun cleanup() = runTest { EnvelopeVault.android(context).wipe() }

    @Test
    fun roundTripAcrossInstancesAndWipe() = runTest {
        val v = EnvelopeVault.android(context)
        v.wipe()
        assertTrue(v.provision())
        val blob = v.wrap("signal".toByteArray(), VaultPurpose.E2EE)
        assertArrayEquals("signal".toByteArray(), EnvelopeVault.android(context).unwrap(blob, VaultPurpose.E2EE))
        try {
            v.unwrap(blob, VaultPurpose.NAMES)
            error("wrong purpose must fail")
        } catch (e: VaultException.Corrupt) {
        }
        v.wipe()
        assertEquals(VaultKeys.MISSING, v.keys())
        try {
            EnvelopeVault.android(context).unwrap(blob, VaultPurpose.E2EE)
            error("wiped vault must fail")
        } catch (e: VaultException.KeyGone) {
        }
    }
}
