package org.wolpmessenger.devicetrust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wolpmessenger.devicetrust.attest.AttestationChain
import org.wolpmessenger.devicetrust.attest.ChainType

class AttestationChainTest {
    @Test
    fun `labels RKP by the provisioning info extension anywhere in the chain`() {
        val rkp = AttestationChain(listOf(cert("with-key-description.pem"), cert("with-provisioning-info.pem"), cert("plain.pem")))
        assertEquals(ChainType.RKP, rkp.chainType)
        assertTrue(rkp.hasKeyDescription)
        assertEquals(3, rkp.encoded().size)
    }

    @Test
    fun `no provisioning info means factory`() {
        val factory = AttestationChain(listOf(cert("plain.pem"), cert("plain.pem")))
        assertEquals(ChainType.FACTORY, factory.chainType)
        assertFalse(factory.hasKeyDescription)
    }
}
