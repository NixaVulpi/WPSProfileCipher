package tech.youko.wpsprofilecipher

import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class TextCipher {
    fun encrypt(plainText: String): String {
        val encrypted = createCipher(Cipher.ENCRYPT_MODE).doFinal(plainText.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(encrypted).toWpsBase64()
    }

    fun decrypt(cipherText: String): String {
        val encrypted = Base64.getDecoder().decode(cipherText.fromWpsBase64())
        val decrypted = createCipher(Cipher.DECRYPT_MODE).doFinal(encrypted)
        return decrypted.toString(StandardCharsets.UTF_8)
    }

    private fun createCipher(mode: Int): Cipher = Cipher.getInstance(AES_TRANSFORMATION).apply {
        init(mode, AES_KEY)
    }

    private fun String.toWpsBase64(): String = replace('+', '_').replace('/', '-').replace('=', '.')

    private fun String.fromWpsBase64(): String = replace('_', '+').replace('-', '/').replace('.', '=')

    companion object {
        private val AES_KEY = SecretKeySpec("F9AF610AE6164C73B78B0A99D8B72890".toByteArray(StandardCharsets.US_ASCII), "AES")
        private const val AES_TRANSFORMATION = "AES/ECB/PKCS5Padding"
    }
}
