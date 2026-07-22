package tech.youko.wpsprofilecipher

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProfileFileTest {
    @Test
    fun `comma-separated cipher values remain a single config string`() {
        val cipherIni = Files.createTempFile("wps-profile", ".ini").toFile()
        val plainJson = Files.createTempFile("wps-profile", ".json").toFile()
        cipherIni.writeText(
            """
            [L10N]
            3FJdw3QKX_8Ocda1ohvap9H_HWpeBrG_9hpfdL1oM7Y.=pH-ngop1ivyPJhzD6NMUKQ.., xLEdt559NPj0AnzHtpEBoA..
            """.trimIndent()
        )

        ProfileFile(TextCipher()).apply {
            loadCipherIni(cipherIni)
            storePlainJson(plainJson)
        }

        val result = com.alibaba.fastjson2.JSON.parseObject(plainJson.readText())
        assertEquals("M/d/yy, 1033", result.getJSONObject("L10N").getString("TX_FIELD_DATE[4]"))
    }

    @Test
    fun `plain JSON rejects array values`() {
        val plainJson = Files.createTempFile("wps-profile", ".json").toFile()
        plainJson.writeText("""{"L10N":{"TX_FIELD_DATE[4]":["M/d/yy","1033"]}}""")

        assertFailsWith<IllegalStateException> {
            ProfileFile(TextCipher()).loadPlainJson(plainJson)
        }
    }

    @Test
    fun `cipher INI is unsigned by default`() {
        val plainJson = Files.createTempFile("wps-profile", ".json").toFile()
        val cipherIni = Files.createTempFile("wps-profile", ".ini").toFile()
        plainJson.writeText("""{"setup":{"enabled":"true"}}""")

        ProfileFile(TextCipher()).apply {
            loadPlainJson(plainJson)
            storeCipherIni(cipherIni)
        }

        assertFalse(cipherIni.readText().contains(";OemSignType1="))
    }

    @Test
    fun `cipher INI can include an OEM signature`() {
        val plainJson = Files.createTempFile("wps-profile", ".json").toFile()
        val cipherIni = Files.createTempFile("wps-profile", ".ini").toFile()
        plainJson.writeText("""{"setup":{"enabled":"true"}}""")

        ProfileFile(TextCipher()).apply {
            loadPlainJson(plainJson)
            storeCipherIni(cipherIni, shouldSign = true)
        }

        assertTrue(cipherIni.readText().contains(";OemSignType1="))
    }
}
