package tech.youko.wpsprofilecipher

import org.ini4j.Ini
import java.io.File
import java.io.StringReader
import java.io.StringWriter
import java.nio.charset.Charset

class ProfileFile(
    private val cipher: TextCipher,
    private val featureCipher: FeatureCipher = FeatureCipher(),
    private val oemSigner: OemSigner = OemSigner()
) {
    private var data: Map<String, Map<String, String>>? = null

    fun loadCipherIni(file: File, charset: Charset = Charsets.UTF_8) {
        val ini = createIni().apply {
            StringReader(file.readText(charset)).use(::load)
        }
        data = ini.entries.associate { (sectionName, section) ->
            sectionName to if (sectionName.equals(FEATURE_SECTION, ignoreCase = true)) {
                section.entries.associate { (key, value) ->
                    val (featureId, featureValue) = featureCipher.decrypt(key, value)
                    featureId.toString() to featureValue.toString()
                }
            } else {
                section.entries.associate { (key, value) ->
                    cipher.decrypt(key) to transformCommaSeparated(value, cipher::decrypt)
                }
            }
        }
    }

    fun storeCipherIni(
        file: File,
        charset: Charset = Charsets.UTF_8,
        shouldSign: Boolean = false,
        headerComment: String? = null
    ) {
        require(headerComment?.none { it == '\r' || it == '\n' } != false) {
            "Header comment cannot contain line breaks."
        }
        val iniText = if (headerComment == null) {
            buildCipherIni()
        } else {
            ";$headerComment\r\n\r\n${buildCipherIni()}"
        }
        val iniBytes = iniText.toByteArray(charset)
        val output = if (shouldSign) oemSigner.appendSignature(iniBytes) else iniBytes
        file.writeBytes(output)
    }

    fun loadPlainIni(file: File, charset: Charset = Charsets.UTF_8) {
        val ini = createIni().apply {
            StringReader(file.readText(charset)).use(::load)
        }
        data = ini.entries.associate { (sectionName, section) ->
            sectionName to section.entries.associate { (key, value) -> key to value }
        }
    }

    fun storePlainIni(file: File, charset: Charset = Charsets.UTF_8) {
        val ini = createIni()
        requireData().forEach { (sectionName, sectionData) ->
            val section = ini.add(sectionName)
            sectionData.forEach { (key, value) -> section[key] = value }
        }
        file.writeText(StringWriter().also(ini::store).toString(), charset)
    }

    private fun buildCipherIni(): String {
        val ini = createIni()
        requireData().forEach { (sectionName, sectionData) ->
            val section = ini.add(sectionName)
            sectionData.forEach { (key, value) ->
                if (sectionName.equals(FEATURE_SECTION, ignoreCase = true)) {
                    val (encryptedKey, encryptedValue) = featureCipher.encrypt(key.toInt(), value.toInt())
                    section[encryptedKey] = encryptedValue
                } else {
                    section[cipher.encrypt(key)] = transformCommaSeparated(value, cipher::encrypt)
                }
            }
        }
        return StringWriter().also(ini::store).toString()
    }

    private fun createIni(): Ini = Ini().apply {
        config.isEscape = false
    }

    private fun requireData(): Map<String, Map<String, String>> =
        requireNotNull(data) { "Data cannot be null." }

    private fun transformCommaSeparated(value: String, transform: (String) -> String): String =
        value.splitToSequence(',').joinToString(", ") { part -> transform(part.trim()) }

    companion object {
        private const val FEATURE_SECTION = "Feature"
    }
}
