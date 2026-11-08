package org.wolpmessenger.devicetrust.io

import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/** Atomic file replacement: temp → fsync → rename (S2 §11). */
internal object AtomicFiles {
    fun write(target: File, bytes: ByteArray) {
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, target.name + ".tmp")
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IOException("rename ${tmp.name} -> ${target.name} failed")
        }
    }
}
