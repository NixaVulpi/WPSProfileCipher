package tech.youko.wpsprofilecipher

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import java.io.File
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val parser = ArgParser("wps-profile-cipher")
    val cipherIniFile by parser.option(
        ArgType.String,
        shortName = "c",
        description = "Cipher INI file (required if text is not provided)"
    )
    val plainJsonFile by parser.option(
        ArgType.String,
        shortName = "p",
        description = "Plain JSON file (required if text is not provided)"
    )
    val text by parser.option(
        ArgType.String,
        shortName = "t",
        description = "Text (if provided, cipherIniFile and plainJsonFile are ignored)"
    )
    val shouldEncrypt by parser.option(
        ArgType.Boolean,
        shortName = "e",
        description = "Should encrypt the content"
    ).default(false)
    try {
        parser.parse(args)
        val wpsCipher = WpsCipher()
        if (text != null) {
            println(
                if (shouldEncrypt) {
                    wpsCipher.encrypt(text!!)
                } else {
                    wpsCipher.decrypt(text!!)
                }
            )
        } else {
            require(cipherIniFile != null && plainJsonFile != null) {
                "Cipher INI file and plain JSON file must be provided if text is not provided."
            }
            val wpsProfileFile = WpsProfileFile(wpsCipher)
            if (shouldEncrypt) {
                wpsProfileFile.loadPlainJson(File(plainJsonFile!!))
                wpsProfileFile.storeCipherIni(File(cipherIniFile!!))
            } else {
                wpsProfileFile.loadCipherIni(File(cipherIniFile!!))
                wpsProfileFile.storePlainJson(File(plainJsonFile!!))
            }
        }
    } catch (e: Exception) {
        if (e.message != null) {
            println("Failure: ${if (e.message!!.endsWith('.')) e.message!! else e.message!!.plus('.')}")
        }
        exitProcess(127)
    }
}
