package tech.youko.wpsprofileconverter

import org.ini4j.Config
import org.ini4j.Ini
import java.io.File

fun convert(originalIniFile: File, newIniFile: File, shouldEncrypt: Boolean, shouldEscape: Boolean = true) {
    val cryptoHelper = WPSCryptoHelper()
    val originalIni = Ini(originalIniFile)
    if (newIniFile.exists()) {
        newIniFile.delete()
    }
    newIniFile.createNewFile()
    val newIni = Ini(newIniFile)
    newIni.config = Config()
    newIni.config.isEscape = shouldEscape
    newIni.config.lineSeparator = if (shouldEscape) "\r\n" else "\n"
    originalIni.forEach { sectionName, sectionData ->
        val newSection = newIni.add(sectionName)
        sectionData.forEach { key, value ->
            if (shouldEncrypt) {
                newSection[cryptoHelper.encrypt(key)] = cryptoHelper.encrypt(value)
            } else {
                val valueBuilder = StringBuilder()
                value.split(',').forEachIndexed { i, v ->
                    val text = cryptoHelper.decrypt(v.trim())
                    valueBuilder.append(if (i > 0) ", $text" else text)
                }
                newSection[cryptoHelper.decrypt(key)] = valueBuilder.toString()
            }
        }
    }
    newIni.store()
}
