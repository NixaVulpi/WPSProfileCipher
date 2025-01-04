package tech.youko.wpsprofilecipher

import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class WpsCipher {
    private val encryptor: Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    private val decryptor: Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    private val key: SecretKeySpec = SecretKeySpec(
        byteArrayOf(
            0x46, 0x39, 0x41, 0x46, 0x36, 0x31, 0x30, 0x41,
            0x45, 0x36, 0x31, 0x36, 0x34, 0x43, 0x37, 0x33,
            0x42, 0x37, 0x38, 0x42, 0x30, 0x41, 0x39, 0x39,
            0x44, 0x38, 0x42, 0x37, 0x32, 0x38, 0x39, 0x30,
        ),
        "AES"
    )

    init {
        encryptor.init(Cipher.ENCRYPT_MODE, key)
        decryptor.init(Cipher.DECRYPT_MODE, key)
    }

    fun encrypt(plainText: String): String {
        val base64TextBuilder = StringBuilder(
            Base64.getEncoder().encodeToString(encryptor.doFinal(plainText.toByteArray()))
        )
        for (i in base64TextBuilder.indices) {
            when (base64TextBuilder[i]) {
                '+' -> base64TextBuilder[i] = '_'
                '/' -> base64TextBuilder[i] = '-'
                '=' -> base64TextBuilder[i] = '.'
            }
        }
        return base64TextBuilder.toString()
    }

    fun decrypt(cipherText: String): String {
        val base64TextBuilder: StringBuilder = StringBuilder(cipherText)
        for (i in base64TextBuilder.indices) {
            when (base64TextBuilder[i]) {
                '_' -> base64TextBuilder[i] = '+'
                '-' -> base64TextBuilder[i] = '/'
                '.' -> base64TextBuilder[i] = '='
            }
        }
        return String(decryptor.doFinal(Base64.getDecoder().decode(base64TextBuilder.toString())))
    }
}
