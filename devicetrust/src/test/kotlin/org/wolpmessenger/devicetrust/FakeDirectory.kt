package org.wolpmessenger.devicetrust

import org.wolpmessenger.devicetrust.api.E2eeException
import org.wolpmessenger.devicetrust.api.E2eeFailure
import org.wolpmessenger.devicetrust.e2ee.DirectoryRecord
import org.wolpmessenger.devicetrust.e2ee.KeyDirectory
import org.wolpmessenger.devicetrust.e2ee.OneTimeKey
import org.wolpmessenger.devicetrust.e2ee.OwnKeys
import org.wolpmessenger.devicetrust.e2ee.OwnRecord
import org.wolpmessenger.devicetrust.e2ee.Passport
import org.wolpmessenger.devicetrust.e2ee.PeerKeys

/**
 * Stand-in key directory with the rules of the real one that the library relies on: one record per
 * account, a one-time key is handed out once, a one-time key id is never taken twice for a device,
 * a new device replaces the record with its keys.
 */
internal class FakeDirectory {
    class Record(val deviceId: String, var keys: OwnKeys, var passport: Passport?) {
        val oneTime = ArrayDeque<OneTimeKey>()
        val seenIds = HashSet<Int>()
        var publications = 0
    }

    val records = HashMap<String, Record>()
    var online = true
    var fetches = 0
    var replenishments = 0

    /** The directory as the session of [user] sees it. */
    fun of(user: String): View = View(user)

    inner class View(private val user: String) : KeyDirectory, OwnRecord {
        private fun reach() {
            if (!online) throw E2eeException(E2eeFailure.NO_NETWORK)
        }

        override suspend fun fetch(user: String): PeerKeys {
            fetches++
            reach()
            val r = records[user] ?: throw E2eeException(E2eeFailure.NO_DEVICE)
            return PeerKeys(r.keys.identityKey, r.keys.registrationId, r.keys.signedPreKey, r.keys.pqPreKey, r.oneTime.removeFirstOrNull(), r.passport)
        }

        override suspend fun record(user: String): DirectoryRecord? {
            reach()
            return records[user]?.let { DirectoryRecord(it.deviceId, it.keys.identityKey, it.passport?.certificates?.first()) }
        }

        override suspend fun count(deviceId: String): Int? {
            reach()
            return records[user]?.takeIf { it.deviceId == deviceId }?.oneTime?.size
        }

        override suspend fun publish(deviceId: String, keys: OwnKeys, passport: Passport) {
            reach()
            val r = records[user]?.takeIf { it.deviceId == deviceId } ?: Record(deviceId, keys, passport).also { records[user] = it }
            r.keys = keys
            r.passport = passport
            r.publications++
            add(r, keys.oneTimePreKeys)
        }

        override suspend fun replenish(deviceId: String, keys: List<OneTimeKey>): Boolean {
            reach()
            val r = records[user]?.takeIf { it.deviceId == deviceId } ?: return false
            replenishments++
            add(r, keys)
            return true
        }

        private fun add(r: Record, keys: List<OneTimeKey>) = keys.filter { r.seenIds.add(it.id) }.forEach(r.oneTime::addLast)
    }
}
