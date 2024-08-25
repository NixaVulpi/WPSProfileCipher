package tech.youko.wpsprofileconverter

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.required
import java.io.File

fun main(args: Array<String>) {
    val parser = ArgParser("WPSProfileConverter")
    val originalFile by parser.option(ArgType.String, shortName = "o", description = "Original INI file").required()
    val newFile by parser.option(ArgType.String, shortName = "n", description = "New INI file").required()
    val shouldEncrypt by parser.option(ArgType.Boolean, shortName = "e", description = "Should encrypt the file").default(false)
    val shouldNotEscape by parser.option(ArgType.Boolean, shortName = "s", description = "Should not escape the content").default(false)
    try {
        parser.parse(args)
        convert(File(originalFile), File(newFile), shouldEncrypt, !shouldNotEscape)
    } catch (e: Exception) {
        println(e.message)
    }
}
