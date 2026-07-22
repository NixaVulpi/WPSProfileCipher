package tech.youko.wpsprofilecipher

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import java.io.File
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    try {
        runCommand(args)
    } catch (exception: Exception) {
        exception.message?.let { message ->
            println("Failure: ${message.ensureTrailingPeriod()}")
        }
        exitProcess(127)
    }
}

private fun runCommand(args: Array<String>) {
    val parser = ArgParser("wps-profile-cipher")
    val cipherIniPath by parser.option(
        ArgType.String,
        fullName = "cipherIniFile",
        shortName = "c",
        description = "Cipher INI file (required if text is not provided)"
    )
    val plainJsonPath by parser.option(
        ArgType.String,
        fullName = "plainJsonFile",
        shortName = "p",
        description = "Plain JSON file (required if text is not provided)"
    )
    val text by parser.option(
        ArgType.String,
        shortName = "t",
        description = "Text (if provided, file options are ignored)"
    )
    val shouldEncrypt by parser.option(
        ArgType.Boolean,
        shortName = "e",
        description = "Encrypt content instead of decrypting it"
    ).default(false)
    val shouldSign by parser.option(
        ArgType.Boolean,
        shortName = "s",
        description = "Append an OEM AES signature when creating a cipher INI file"
    ).default(false)
    val algorithm by parser.option(
        ArgType.String,
        fullName = "algorithm",
        shortName = "a",
        description = "Text algorithm: profile (AES, default) or feature (IDEA/C64)"
    ).default("profile")

    parser.parse(args)
    val cipher = TextCipher()
    if (text != null) {
        require(!shouldSign) { "OEM signing is only available for JSON to INI conversion." }
        println(transformText(text!!, algorithm, shouldEncrypt, cipher, FeatureCipher()))
        return
    }

    require(algorithm.equals("profile", ignoreCase = true)) {
        "The algorithm option only applies to text mode; file conversion detects the Feature section automatically."
    }

    require(cipherIniPath != null && plainJsonPath != null) {
        "Cipher INI file and plain JSON file must be provided if text is not provided."
    }
    require(!shouldSign || shouldEncrypt) {
        "OEM signing is only available for JSON to INI conversion."
    }

    ProfileFile(cipher).apply {
        if (shouldEncrypt) {
            loadPlainJson(File(plainJsonPath!!))
            storeCipherIni(File(cipherIniPath!!), shouldSign = shouldSign)
        } else {
            loadCipherIni(File(cipherIniPath!!))
            storePlainJson(File(plainJsonPath!!))
        }
    }
}

private fun transformText(
    text: String,
    algorithm: String,
    shouldEncrypt: Boolean,
    cipher: TextCipher,
    featureCipher: FeatureCipher
): String = when (algorithm.lowercase()) {
    "profile" -> if (shouldEncrypt) cipher.encrypt(text) else cipher.decrypt(text)
    "feature" -> {
        val (key, value) = splitEntry(text)
        if (shouldEncrypt) {
            val (encryptedKey, encryptedValue) = featureCipher.encrypt(key.toInt(), value.toInt())
            "$encryptedKey=$encryptedValue"
        } else {
            val (featureId, featureValue) = featureCipher.decrypt(key, value)
            "$featureId=$featureValue"
        }
    }
    else -> throw IllegalArgumentException("Algorithm must be 'profile' or 'feature'.")
}

private fun splitEntry(text: String): Pair<String, String> {
    val separator = text.indexOf('=')
    require(separator > 0 && separator < text.lastIndex) {
        "Feature text must be a key=value pair."
    }
    return text.substring(0, separator) to text.substring(separator + 1)
}

private fun String.ensureTrailingPeriod(): String = if (endsWith('.')) this else "$this."
