package tech.youko.wpsprofilecipher

import com.alibaba.fastjson2.JSON
import com.alibaba.fastjson2.JSONObject
import com.alibaba.fastjson2.JSONWriter
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
        val ini = StringReader(file.readText(charset)).use(::Ini)
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

    fun storeCipherIni(file: File, charset: Charset = Charsets.UTF_8, shouldSign: Boolean = false) {
        val iniBytes = buildCipherIni().toByteArray(charset)
        val output = if (shouldSign) oemSigner.appendSignature(iniBytes) else iniBytes
        file.writeBytes(output)
    }

    fun loadPlainJson(file: File, charset: Charset = Charsets.UTF_8) {
        val root = file.reader(charset).use(JSON::parseObject)
        data = root.entries.associate { (sectionName, sectionValue) ->
            check(sectionValue is Map<*, *>) { "Section data must be an object." }
            sectionName to sectionValue.entries.associate { (key, value) ->
                check(key is String) { "Key must be a string." }
                check(value is String) { "Value must be a string." }
                key to value
            }
        }
    }

    fun storePlainJson(file: File, charset: Charset = Charsets.UTF_8) {
        val json = requireData().entries.associateTo(JSONObject()) { (sectionName, section) ->
            sectionName to JSONObject(section)
        }
        file.writeText(
            json.toString(JSONWriter.Feature.PrettyFormat, JSONWriter.Feature.WriteMapNullValue),
            charset
        )
    }

    private fun buildCipherIni(): String {
        val ini = Ini()
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

    private fun requireData(): Map<String, Map<String, String>> =
        requireNotNull(data) { "Data cannot be null." }

    private fun transformCommaSeparated(value: String, transform: (String) -> String): String =
        value.splitToSequence(',').joinToString(", ") { part -> transform(part.trim()) }

    companion object {
        private const val FEATURE_SECTION = "Feature"
    }
}
