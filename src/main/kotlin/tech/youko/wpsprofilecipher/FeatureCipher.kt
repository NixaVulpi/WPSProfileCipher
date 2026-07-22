package tech.youko.wpsprofilecipher

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class FeatureCipher {
    fun encrypt(featureId: Int, value: Int): Pair<String, String> =
        encryptText(featureId.toString()) to encryptText("$featureId:$value")

    fun decrypt(key: String, value: String): Pair<Int, Int> {
        val featureId = decryptText(key).toInt()
        val parts = decryptText(value).split(':', limit = 2)
        require(parts.size == 2 && parts[0].toInt() == featureId) {
            "Feature key and value IDs do not match."
        }
        return featureId to parts[1].toInt()
    }

    fun encryptText(plainText: String): String {
        val plain = plainText.toByteArray(StandardCharsets.US_ASCII)
        val padded = plain.copyOf((plain.size / BLOCK_SIZE + 1) * BLOCK_SIZE)
        val encrypted = transformBlocks(padded, encrypt = true)
        val digest = md5(encrypted)
        val framed = encrypted + byteArrayOf(digest[0], digest[8], TRAILER_TYPE)
        return c64Encode(swapObfuscationBits(framed))
    }

    fun decryptText(cipherText: String): String {
        val framed = swapObfuscationBits(c64Decode(cipherText))
        require(framed.size >= BLOCK_SIZE + 3 && (framed.size - 3) % BLOCK_SIZE == 0) {
            "Invalid Feature payload length."
        }
        val encrypted = framed.copyOfRange(0, framed.size - 3)
        val trailer = framed.copyOfRange(framed.size - 3, framed.size)
        val digest = md5(encrypted)
        val expected = byteArrayOf(digest[0], digest[8], TRAILER_TYPE)
        require(trailer.contentEquals(expected)) { "Invalid Feature checksum or type marker." }
        val plain = transformBlocks(encrypted, encrypt = false)
        val terminator = plain.indexOf(0)
        val length = if (terminator >= 0) terminator else plain.size
        return plain.copyOf(length).toString(StandardCharsets.US_ASCII)
    }

    private fun transformBlocks(input: ByteArray, encrypt: Boolean): ByteArray {
        val output = ByteArray(input.size)
        input.indices.step(BLOCK_SIZE).forEach { offset ->
            transformBlock(input, offset, output, offset, encrypt)
        }
        return output
    }

    private fun transformBlock(input: ByteArray, inputOffset: Int, output: ByteArray, outputOffset: Int, encrypt: Boolean) {
        var x1 = readWord(input, inputOffset)
        var x2 = readWord(input, inputOffset + 2)
        var x3 = readWord(input, inputOffset + 4)
        var x4 = readWord(input, inputOffset + 6)

        if (encrypt) {
            var keyOffset = 0
            repeat(8) {
                val y1 = multiply(x1, subKeys[keyOffset++])
                val y2 = add(x2, subKeys[keyOffset++])
                val y3 = add(x3, subKeys[keyOffset++])
                val y4 = multiply(x4, subKeys[keyOffset++])
                val t0 = multiply(y1 xor y3, subKeys[keyOffset++])
                val t1 = multiply(add(y2 xor y4, t0), subKeys[keyOffset++])
                val mixed = add(t0, t1)
                x1 = y1 xor t1
                x2 = y3 xor t1
                x3 = y2 xor mixed
                x4 = y4 xor mixed
            }
            writeWord(output, outputOffset, multiply(x1, subKeys[48]))
            writeWord(output, outputOffset + 2, add(x3, subKeys[49]))
            writeWord(output, outputOffset + 4, add(x2, subKeys[50]))
            writeWord(output, outputOffset + 6, multiply(x4, subKeys[51]))
            return
        }

        val cipher2 = x2
        val cipher3 = x3
        x1 = multiply(x1, multiplicativeInverse(subKeys[48]))
        x3 = subtract(cipher2, subKeys[49])
        x2 = subtract(cipher3, subKeys[50])
        x4 = multiply(x4, multiplicativeInverse(subKeys[51]))
        for (round in 7 downTo 0) {
            val keyOffset = round * 6
            val t0 = multiply(x1 xor x2, subKeys[keyOffset + 4])
            val t1 = multiply(add(x3 xor x4, t0), subKeys[keyOffset + 5])
            val mixed = add(t0, t1)
            val y1 = x1 xor t1
            val y3 = x2 xor t1
            val y2 = x3 xor mixed
            val y4 = x4 xor mixed
            x1 = multiply(y1, multiplicativeInverse(subKeys[keyOffset]))
            x2 = subtract(y2, subKeys[keyOffset + 1])
            x3 = subtract(y3, subKeys[keyOffset + 2])
            x4 = multiply(y4, multiplicativeInverse(subKeys[keyOffset + 3]))
        }
        writeWord(output, outputOffset, x1)
        writeWord(output, outputOffset + 2, x2)
        writeWord(output, outputOffset + 4, x3)
        writeWord(output, outputOffset + 6, x4)
    }

    private fun swapObfuscationBits(input: ByteArray): ByteArray {
        val result = input.copyOf(input.size + 1)
        val trailerStart = result.size - 4
        for (bit in intArrayOf(0, 4)) {
            val left = (result[0].toInt() ushr bit) and 1
            val right = (result[trailerStart].toInt() ushr bit) and 1
            if (left != right) {
                result[0] = (result[0].toInt() xor (1 shl bit)).toByte()
                result[trailerStart] = (result[trailerStart].toInt() xor (1 shl bit)).toByte()
            }
        }
        return result.copyOf(result.size - 1)
    }

    private fun c64Encode(input: ByteArray): String = buildString {
        var accumulator = 0L
        var bitCount = 0
        for (byte in input) {
            accumulator = accumulator or ((byte.toInt() and 0xFF).toLong() shl bitCount)
            bitCount += 8
            while (bitCount >= 6) {
                append(C64_ALPHABET[(accumulator and 0x3F).toInt()])
                accumulator = accumulator ushr 6
                bitCount -= 6
            }
        }
        if (bitCount > 0) append(C64_ALPHABET[(accumulator and 0x3F).toInt()])
    }

    private fun c64Decode(input: String): ByteArray {
        val output = ArrayList<Byte>()
        var accumulator = 0L
        var bitCount = 0
        for (character in input) {
            val value = C64_ALPHABET.indexOf(character)
            require(value >= 0) { "Invalid Feature C64 character: '$character'." }
            accumulator = accumulator or (value.toLong() shl bitCount)
            bitCount += 6
            while (bitCount >= 8) {
                output += (accumulator and 0xFF).toByte()
                accumulator = accumulator ushr 8
                bitCount -= 8
            }
        }
        return output.toByteArray()
    }

    private fun expandKey(key: ByteArray): IntArray = IntArray(52).also { expanded ->
        for (index in 0 until 8) expanded[index] = readWord(key, index * 2)
        for (index in 8 until 52) {
            expanded[index] = when (index and 7) {
                in 0..5 -> (expanded[index - 7] shl 9) or (expanded[index - 6] ushr 7)
                6 -> (expanded[index - 7] shl 9) or (expanded[index - 14] ushr 7)
                else -> (expanded[index - 15] shl 9) or (expanded[index - 14] ushr 7)
            } and WORD_MASK
        }
    }

    private fun multiply(left: Int, right: Int): Int {
        val normalizedLeft = if (left == 0) IDEA_MODULUS - 1L else left.toLong()
        val normalizedRight = if (right == 0) IDEA_MODULUS - 1L else right.toLong()
        return ((normalizedLeft * normalizedRight) % IDEA_MODULUS).toInt() and WORD_MASK
    }

    private fun multiplicativeInverse(value: Int): Int {
        if (value == 0) return 0
        var oldR = IDEA_MODULUS
        var r = value.toLong()
        var oldT = 0L
        var t = 1L
        while (r != 0L) {
            val quotient = oldR / r
            val nextR = oldR - quotient * r
            oldR = r
            r = nextR
            val nextT = oldT - quotient * t
            oldT = t
            t = nextT
        }
        return ((oldT % IDEA_MODULUS + IDEA_MODULUS) % IDEA_MODULUS).toInt() and WORD_MASK
    }

    private fun add(left: Int, right: Int): Int = (left + right) and WORD_MASK
    private fun subtract(left: Int, right: Int): Int = (left - right) and WORD_MASK
    private fun readWord(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun writeWord(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun md5(bytes: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(bytes)

    private val subKeys = expandKey(md5("wps".toByteArray(StandardCharsets.US_ASCII)))

    companion object {
        private const val C64_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
        private const val BLOCK_SIZE = 8
        private const val WORD_MASK = 0xFFFF
        private const val IDEA_MODULUS = 65537L
        private const val TRAILER_TYPE: Byte = 1
    }
}
