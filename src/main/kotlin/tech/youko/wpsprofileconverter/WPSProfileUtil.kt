package tech.youko.wpsprofileconverter

import org.ini4j.Config
import org.ini4j.Ini
import org.ini4j.spi.EscapeTool
import java.io.File

fun convertText(text: String, shouldEncrypt: Boolean, shouldEscape: Boolean = true): String {
    return if (shouldEncrypt) {
        val content = if (shouldEscape) EscapeTool.getInstance().unescape(text) else text
        WPSCryptoHelper.encrypt(content)
    } else {
        val content = WPSCryptoHelper.decrypt(text)
        if (shouldEscape) EscapeTool.getInstance().escape(content) else content
    }
}

fun convertProfileFile(originalIniFile: File, newIniFile: File, shouldEncrypt: Boolean, shouldEscape: Boolean = true) {
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
                newSection[WPSCryptoHelper.encrypt(key)] = WPSCryptoHelper.encrypt(value)
            } else {
                val valueBuilder = StringBuilder()
                value.split(',').forEachIndexed { i, v ->
                    val text = WPSCryptoHelper.decrypt(v.trim())
                    valueBuilder.append(if (i > 0) ", $text" else text)
                }
                newSection[WPSCryptoHelper.decrypt(key)] = valueBuilder.toString()
            }
        }
    }
    newIni.store()
}
