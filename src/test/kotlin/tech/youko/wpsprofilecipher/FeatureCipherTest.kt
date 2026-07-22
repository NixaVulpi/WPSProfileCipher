package tech.youko.wpsprofilecipher

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals

class FeatureCipherTest {
    private val cipher = FeatureCipher()

    @Test
    fun `known security document sample decrypts`() {
        assertEquals(
            16777331 to 0,
            cipher.decrypt(
                "5HsDS8UAjZnKSU9I2xbCubqA10",
                "KHsDS8UAjZn4U3A385v-NVsE10"
            )
        )
    }

    @Test
    fun `known security document sample encrypts byte for byte`() {
        assertEquals(
            "5HsDS8UAjZnKSU9I2xbCubqA10" to "KHsDS8UAjZn4U3A385v-NVsE10",
            cipher.encrypt(16777331, 0)
        )
    }
}
