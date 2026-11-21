package com.openvireo.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.openvireo.core.hosts.defaultHost
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Loads libov_ffi.so through JNA on a device or emulator and makes a few offline calls. Not run in
 * CI (no emulator there): `./gradlew :core-android:connectedAndroidTest` with a device attached.
 */
@RunWith(AndroidJUnit4::class)
class LoadTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun versionIsSemver() {
        assertEquals(3, version().split('.').size)
    }

    @Test
    fun sha256OfAbc() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex(sha256("abc".toByteArray())))
    }

    @Test
    fun defaultHostBuildsAClient() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        OvClient(ClientConfig(DeviceInfo(null, "android-smoke", Platform.ANDROID), true, null), defaultHost(context)).use { client ->
            assertEquals("android-smoke", client.config().device.name)
        }
    }
}
