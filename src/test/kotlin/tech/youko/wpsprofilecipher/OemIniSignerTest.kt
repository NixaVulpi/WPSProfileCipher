package tech.youko.wpsprofilecipher

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OemIniSignerTest {
    @Test
    fun `appendSignature returns content with a verifiable OEM AES signature`() {
        val content = "[setup]\r\nkey=value".toByteArray(StandardCharsets.UTF_8)
        val iv = ByteArray(16) { it.toByte() }

        val output = OemSigner(FixedSecureRandom(iv)).appendSignature(content)

        val headerOffset = output.size - SIGNATURE_SIZE
        assertContentEquals(content + "\r\n".toByteArray(), output.copyOfRange(0, headerOffset))
        assertContentEquals(OemSigner.SIGNATURE_HEADER, output.copyOfRange(headerOffset, headerOffset + HEADER_SIZE))

        val encoded = output.copyOfRange(headerOffset + HEADER_SIZE, output.size).toString(StandardCharsets.US_ASCII)
        assertEquals(ENCODED_PAYLOAD_SIZE, encoded.length)
        assertTrue(encoded.all { character -> character.isDigit() || character in 'A'..'F' })

        val payload = encoded.hexToBytes()
        val recoveredIv = ByteArray(16) { index ->
            (payload[index].toInt() xor OemSigner.IV_MASK[index].toInt()).toByte()
        }
        assertContentEquals(iv, recoveredIv)

        val decryptedDigest = Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(Cipher.DECRYPT_MODE, OemSigner.AES_KEY, IvParameterSpec(recoveredIv))
            doFinal(payload.copyOfRange(16, payload.size)).toString(StandardCharsets.US_ASCII)
        }
        val expectedDigest = MessageDigest.getInstance("MD5")
            .digest(output.copyOfRange(0, headerOffset + HEADER_SIZE))
            .toUpperHex()
        assertEquals(expectedDigest, decryptedDigest)
    }

    private fun String.hexToBytes(): ByteArray =
        chunked(2).map { pair -> pair.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.toUpperHex(): String =
        joinToString(separator = "") { byte -> "%02X".format(byte.toInt() and 0xFF) }

    private class FixedSecureRandom(private val bytes: ByteArray) : SecureRandom() {
        override fun nextBytes(target: ByteArray) {
            bytes.copyInto(target)
        }
    }

    companion object {
        private const val HEADER_SIZE = 14
        private const val ENCODED_PAYLOAD_SIZE = 128
        private const val SIGNATURE_SIZE = HEADER_SIZE + ENCODED_PAYLOAD_SIZE
    }
}
