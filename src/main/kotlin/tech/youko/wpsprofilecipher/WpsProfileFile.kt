package tech.youko.wpsprofilecipher

import com.alibaba.fastjson2.JSON
import com.alibaba.fastjson2.JSONArray
import com.alibaba.fastjson2.JSONObject
import com.alibaba.fastjson2.JSONWriter
import org.ini4j.Ini
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.nio.charset.Charset

class WpsProfileFile(private val cipher: WpsCipher) {
    private var data: Map<*, *>? = null

    fun loadCipherIni(file: File, charset: Charset = Charsets.UTF_8) {
        val fileReader = FileReader(file, charset)
        data = Ini(fileReader).entries.fold(HashMap<String, Any>()) { sectionMap, (sectionName, sectionData) ->
            sectionMap.apply {
                this[sectionName] = sectionData.entries.fold(HashMap<String, Any>()) { dataMap, (key, value) ->
                    dataMap.apply {
                        this[cipher.decrypt(key)] = if (value.contains(',')) {
                            value.split(',').map {
                                cipher.decrypt(it.trim())
                            }
                        } else {
                            cipher.decrypt(value)
                        }
                    }
                }
            }
        }
    }

    fun storeCipherIni(file: File, charset: Charset = Charsets.UTF_8) {
        requireNotNull(data) { "Data cannot be null." }
        FileWriter(file, charset).use { fileWriter ->
            data!!.entries.fold(Ini()) { ini, (sectionName, sectionData) ->
                check(sectionName is String) { "Section name must be a string." }
                check(sectionData is HashMap<*, *>) { "Section data must be a HashMap." }
                ini.apply {
                    val section = this.add(sectionName)
                    sectionData.forEach { (key, value) ->
                        check(key is String) { "Key must be a string." }
                        section[cipher.encrypt(key)] = if (value is List<*>) {
                            check(value.size > 1) { "List value must have at least 2 elements." }
                            value.joinToString(", ") {
                                check(it is String) { "List value must be a string." }
                                cipher.encrypt(it)
                            }
                        } else {
                            check(value is String) { "Value must be a string or a list of strings." }
                            cipher.encrypt(value)
                        }
                    }
                }
            }.store(fileWriter)
        }
    }

    fun loadPlainJson(file: File, charset: Charset = Charsets.UTF_8) {
        val fileReader = FileReader(file, charset)
        data = JSON.parseObject(fileReader)
    }

    fun storePlainJson(file: File, charset: Charset = Charsets.UTF_8) {
        requireNotNull(data) { "Data cannot be null." }
        FileWriter(file, charset).use { fileWriter ->
            data!!.entries.fold(JSONObject()) { json, (sectionName, sectionData) ->
                check(sectionName is String) { "Section name must be a string." }
                check(sectionData is HashMap<*, *>) { "Section data must be a HashMap." }
                json.apply {
                    this[sectionName] = sectionData.entries.fold(JSONObject()) { subJson, (key, value) ->
                        check(key is String) { "Key must be a string." }
                        subJson.apply {
                            if (value is List<*>) {
                                check(value.size > 1) { "List value must have at least 2 elements." }
                                subJson[key] = value.fold(JSONArray()) { array, it ->
                                    check(it is String) { "List value must be a string." }
                                    array.apply {
                                        array.add(it)
                                    }
                                }
                            } else {
                                check(value is String) { "Value must be a string or a list of strings." }
                                subJson[key] = value
                            }
                        }
                    }
                }
            }.toString(
                JSONWriter.Feature.PrettyFormat,
                JSONWriter.Feature.WriteMapNullValue
            ).let {
                fileWriter.write(it)
            }
        }
    }
}
