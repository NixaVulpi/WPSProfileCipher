package tech.youko.wpsprofilecipher

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProfileFileTest {
    @Test
    fun `profile file automatically uses feature codec for Feature section`() {
        val cipherIni = Files.createTempFile("wps-feature", ".ini").toFile()
        val plainIni = Files.createTempFile("wps-feature-plain", ".ini").toFile()
        plainIni.writeText("[Feature]\n16777331=0\n")

        ProfileFile(TextCipher()).apply {
            loadPlainIni(plainIni)
            storeCipherIni(cipherIni)
        }

        ProfileFile(TextCipher()).apply {
            loadCipherIni(cipherIni)
            storePlainIni(plainIni)
        }
        assertEquals(true, plainIni.readText().contains("16777331 = 0"))
    }
    
    @Test
    fun `cipher INI decrypts to plain INI`() {
        val cipherIni = Files.createTempFile("wps-profile-cipher", ".ini").toFile()
        val plainIni = Files.createTempFile("wps-profile-plain", ".ini").toFile()
        cipherIni.writeText(
            """
            [L10N]
            3FJdw3QKX_8Ocda1ohvap9H_HWpeBrG_9hpfdL1oM7Y.=pH-ngop1ivyPJhzD6NMUKQ.., xLEdt559NPj0AnzHtpEBoA..
            """.trimIndent()
        )

        ProfileFile(TextCipher()).apply {
            loadCipherIni(cipherIni)
            storePlainIni(plainIni)
        }

        val output = plainIni.readText()
        assertTrue(output.contains("TX_FIELD_DATE[4] = M/d/yy, 1033"))
    }

    @Test
    fun `plain INI preserves JSON-shaped values without quote escaping`() {
        val plainIni = Files.createTempFile("wps-profile-plain", ".ini").toFile()
        val cipherIni = Files.createTempFile("wps-profile-cipher", ".ini").toFile()
        plainIni.writeText(
            """
            [default]
            SNOverNumberLimit={"support":false}
            WindowsPath=C:\Program Files\WPS Office
            """.trimIndent()
        )

        ProfileFile(TextCipher()).apply {
            loadPlainIni(plainIni)
            storeCipherIni(cipherIni)
            loadCipherIni(cipherIni)
            storePlainIni(plainIni)
        }

        assertTrue(plainIni.readText().contains("{\"support\":false}"))
        assertFalse(plainIni.readText().contains("&quot;"))
        assertFalse(plainIni.readText().contains("\\\"support\\\""))
        assertTrue(plainIni.readText().contains("C:\\Program Files\\WPS Office"))
    }

    @Test
    fun `cipher INI is written without escape sequences`() {
        val plainIni = Files.createTempFile("wps-profile-plain", ".ini").toFile()
        val cipherIni = Files.createTempFile("wps-profile-cipher", ".ini").toFile()
        plainIni.writeText(
            """
            [default]
            SNOverNumberLimit={"support":false}

            [Feature]
            16777331=0
            """.trimIndent()
        )

        ProfileFile(TextCipher()).apply {
            loadPlainIni(plainIni)
            storeCipherIni(cipherIni)
        }

        val output = cipherIni.readText()
        assertFalse(output.contains('\\'))
        assertTrue(output.contains("HTPDtVFg3n-uoBiUYsZZ0Rw4cgQP_aqsrL3azzCMIZI."))
        assertTrue(output.contains("5HsDS8UAjZnKSU9I2xbCubqA10"))
    }

    @Test
    fun `plain and cipher INI round trip`() {
        val plainIni = Files.createTempFile("wps-profile-plain", ".ini").toFile()
        val resultIni = Files.createTempFile("wps-profile-result", ".ini").toFile()
        val cipherIni = Files.createTempFile("wps-profile-cipher", ".ini").toFile()
        plainIni.writeText(
            """
            [setup]
            enabled=true

            [Feature]
            16777331=0
            """.trimIndent()
        )

        ProfileFile(TextCipher()).apply {
            loadPlainIni(plainIni)
            storeCipherIni(cipherIni)
            loadCipherIni(cipherIni)
            storePlainIni(resultIni)
        }

        val output = resultIni.readText()
        assertTrue(output.contains("enabled = true"))
        assertTrue(output.contains("16777331 = 0"))
    }

    @Test
    fun `cipher INI is unsigned by default`() {
        val plainIni = createSimpleIni()
        val cipherIni = Files.createTempFile("wps-profile", ".ini").toFile()

        ProfileFile(TextCipher()).apply {
            loadPlainIni(plainIni)
            storeCipherIni(cipherIni)
        }

        assertFalse(cipherIni.readText().contains(";OemSignType1="))
    }

    @Test
    fun `cipher INI can include an OEM signature`() {
        val plainIni = createSimpleIni()
        val cipherIni = Files.createTempFile("wps-profile", ".ini").toFile()

        ProfileFile(TextCipher()).apply {
            loadPlainIni(plainIni)
            storeCipherIni(cipherIni, shouldSign = true)
        }

        assertTrue(cipherIni.readText().contains(";OemSignType1="))
    }

    @Test
    fun `header comment precedes INI and is included before signature`() {
        val plainIni = createSimpleIni()
        val cipherIni = Files.createTempFile("wps-profile", ".ini").toFile()

        ProfileFile(TextCipher()).apply {
            loadPlainIni(plainIni)
            storeCipherIni(
                cipherIni,
                shouldSign = true,
                headerComment = "WPS OEM configuration"
            )
        }

        val output = cipherIni.readText()
        assertTrue(output.startsWith(";WPS OEM configuration\r\n\r\n[setup]"))
        val signatureOffset = output.indexOf(";OemSignType1=")
        assertTrue(signatureOffset > output.indexOf("[setup]"))
    }

    @Test
    fun `header comment rejects line breaks`() {
        val plainIni = createSimpleIni()
        val cipherIni = Files.createTempFile("wps-profile", ".ini").toFile()
        val profile = ProfileFile(TextCipher()).apply { loadPlainIni(plainIni) }

        kotlin.test.assertFailsWith<IllegalArgumentException> {
            profile.storeCipherIni(cipherIni, headerComment = "first\nsecond")
        }
    }

    private fun createSimpleIni() = Files.createTempFile("wps-profile-plain", ".ini").toFile().apply {
        writeText("[setup]\nenabled=true\n")
    }
}
