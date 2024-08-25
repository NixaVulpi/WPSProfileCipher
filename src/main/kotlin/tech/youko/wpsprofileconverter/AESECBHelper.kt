package tech.youko.wpsprofileconverter

import java.security.Key
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

open class AESECBHelper(secretKey: String, fillingMethod: String) {
    private val key: Key = SecretKeySpec(secretKey.toByteArray(), "AES")
    private val transformation: String = "AES/ECB/$fillingMethod"

    open fun encrypt(string: String): String {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.getEncoder().encodeToString(cipher.doFinal(string.toByteArray()))
    }

    open fun decrypt(base64: String): String {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, key)
        return String(cipher.doFinal(Base64.getDecoder().decode(base64)))
    }
}
