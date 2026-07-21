package tech.youko.wpsprofilecipher

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class OemSigner(private val secureRandom: SecureRandom = SecureRandom()) {
    fun appendSignature(content: ByteArray): ByteArray {
        val normalizedContent = content.ensureTrailingLineBreak()
        val digestInput = normalizedContent + SIGNATURE_HEADER
        val digestHex = MessageDigest.getInstance(MD5)
            .digest(digestInput)
            .toUpperHex()
            .toByteArray(StandardCharsets.US_ASCII)
        val iv = ByteArray(AES_BLOCK_SIZE).also(secureRandom::nextBytes)
        val encryptedDigest = Cipher.getInstance(AES_TRANSFORMATION).run {
            init(Cipher.ENCRYPT_MODE, AES_KEY, IvParameterSpec(iv))
            doFinal(digestHex)
        }
        val maskedIv = ByteArray(iv.size) { index ->
            (iv[index].toInt() xor IV_MASK[index].toInt()).toByte()
        }
        val encodedSignature = (maskedIv + encryptedDigest)
            .toUpperHex()
            .toByteArray(StandardCharsets.US_ASCII)

        return normalizedContent + SIGNATURE_HEADER + encodedSignature
    }

    private fun ByteArray.ensureTrailingLineBreak(): ByteArray =
        if (lastOrNull() == CARRIAGE_RETURN || lastOrNull() == LINE_FEED) this else this + CRLF

    private fun ByteArray.toUpperHex(): String =
        joinToString(separator = "") { byte -> "%02X".format(byte.toInt() and 0xFF) }

    companion object {
        internal val SIGNATURE_HEADER = ";OemSignType1=".toByteArray(StandardCharsets.US_ASCII)
        internal val IV_MASK = "S3kP06v2Ne04lDeX".toByteArray(StandardCharsets.US_ASCII)
        internal val AES_KEY = SecretKeySpec("F9AF610AE6164C73B78B0A99D8B72890".toByteArray(StandardCharsets.US_ASCII), "AES")

        private val CRLF = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())
        private const val CARRIAGE_RETURN: Byte = 13
        private const val LINE_FEED: Byte = 10
        private const val AES_BLOCK_SIZE = 16
        private const val AES_TRANSFORMATION = "AES/CBC/PKCS5Padding"
        private const val MD5 = "MD5"
    }
}
