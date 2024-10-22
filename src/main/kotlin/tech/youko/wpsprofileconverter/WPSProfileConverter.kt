package tech.youko.wpsprofileconverter

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import java.io.File

fun main(args: Array<String>) {
    val parser = ArgParser("wps-profile-converter")
    val originalFile by parser.option(ArgType.String, shortName = "o", description = "Original INI file (required if text is not provided)")
    val newFile by parser.option(ArgType.String, shortName = "n", description = "New INI file (required if text is not provided)")
    val text by parser.option(ArgType.String, shortName = "t", description = "Text (if provided, originalFile and newFile are ignored)")
    val shouldEncrypt by parser.option(ArgType.Boolean, shortName = "e", description = "Should encrypt the content").default(false)
    val shouldNotEscape by parser.option(ArgType.Boolean, shortName = "s", description = "Should not escape the content").default(false)
    try {
        parser.parse(args)
        if (text != null) {
            println(convertText(text!!, shouldEncrypt, !shouldNotEscape))
        } else {
            if (originalFile == null || newFile == null) {
                throw IllegalArgumentException("Original file and new file must be provided if text is not provided.")
            }
            convertProfileFile(File(originalFile!!), File(newFile!!), shouldEncrypt, !shouldNotEscape)
        }
    } catch (e: Exception) {
        println(e.message)
    }
}
