package tech.youko.wpsprofilecipher

import kotlin.test.Test
import kotlin.test.assertEquals

class TextCipherTest {
    private val cipher = TextCipher()

    @Test
    fun `known profile key and value decrypt`() {
        assertEquals(
            "SNOverNumberLimit",
            cipher.decrypt("HTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI.")
        )
        assertEquals(
            "{\"support\":false}",
            cipher.decrypt("w9i9uWkc6RN4cPeNd-bnm-PisbsDFedPvWwc0De4kWE.")
        )
    }

    @Test
    fun `known profile key and value encrypt byte for byte`() {
        assertEquals(
            "HTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI.",
            cipher.encrypt("SNOverNumberLimit")
        )
        assertEquals(
            "w9i9uWkc6RN4cPeNd-bnm-PisbsDFedPvWwc0De4kWE.",
            cipher.encrypt("{\"support\":false}")
        )
    }

    @Test
    fun `unicode text round trips`() {
        val plainText = "配置文件 / profile"
        assertEquals(plainText, cipher.decrypt(cipher.encrypt(plainText)))
    }
}
