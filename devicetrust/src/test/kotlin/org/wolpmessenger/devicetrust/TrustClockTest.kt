package org.wolpmessenger.devicetrust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.wolpmessenger.devicetrust.clock.ClockAnchor
import org.wolpmessenger.devicetrust.clock.ClockSource
import org.wolpmessenger.devicetrust.clock.TrustClock
import java.time.Instant

class TrustClockTest {
    private class Src(var elapsed: Long = 1_000, var system: Long = 0, var boot: Int = 5) : ClockSource {
        override fun elapsedRealtime() = elapsed
        override fun systemEpochMs() = system
        override fun bootCount() = boot
    }

    private val serverDate = "Sun, 08 Nov 2026 19:08:53 GMT"
    private val serverMs = Instant.parse("2026-11-08T19:08:53Z").toEpochMilli()

    @Test
    fun `server time advances with elapsedRealtime and ignores the device clock`() {
        val src = Src(system = 42)
        val clock = TrustClock(src)
        assertNull(clock.trustNow())
        assertEquals(Instant.ofEpochMilli(42), clock.now())

        val anchor = clock.onPinnedResponse(serverDate)
        assertEquals(ClockAnchor(serverMs, 1_000, 5), anchor)
        src.elapsed += 60_000
        src.system += 2L * 24 * 3600 * 1000 // user moves the clock two days ahead
        assertEquals(Instant.ofEpochMilli(serverMs + 60_000), clock.trustNow())
        assertEquals(clock.trustNow(), clock.now())
    }

    @Test
    fun `after a reboot the anchor is unusable until the next pinned response`() {
        val src = Src(system = 7)
        val clock = TrustClock(src, ClockAnchor(serverMs, 900, bootCount = 4))
        assertNull(clock.trustNow())
        assertEquals(Instant.ofEpochMilli(7), clock.now())
        clock.onPinnedResponse(serverDate)
        assertEquals(Instant.ofEpochMilli(serverMs), clock.trustNow())
    }

    @Test
    fun `unknown boot count disables server time`() {
        val clock = TrustClock(Src(boot = -1))
        clock.onPinnedResponse(serverDate)
        assertNull(clock.trustNow())
    }

    @Test
    fun `missing or bad Date header keeps the old anchor`() {
        val clock = TrustClock(Src())
        clock.onPinnedResponse(serverDate)
        val before = clock.anchor()
        assertNull(clock.onPinnedResponse(null))
        assertNull(clock.onPinnedResponse("yesterday"))
        assertEquals(before, clock.anchor())
    }
}
