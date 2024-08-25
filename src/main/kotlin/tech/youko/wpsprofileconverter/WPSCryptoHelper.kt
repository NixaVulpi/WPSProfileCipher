package tech.youko.wpsprofileconverter

class WPSCryptoHelper : AESHelper(
    "F9AF610AE6164C73B78B0A99D8B72890",
    "ECB/PKCS5Padding"
) {
    override fun encrypt(string: String): String {
        return super.encrypt(string)
            .replace('+', '_')
            .replace('/', '-')
            .replace('=', '.')
    }

    override fun decrypt(base64: String): String {
        return super.decrypt(
            base64
                .replace('_', '+')
                .replace('-', '/')
                .replace('.', '=')
        )
    }
}
