package papersplz

import java.security.NoSuchAlgorithmException
import javax.crypto.spec.SecretKeySpec

interface CryptoProvider {
    byte[] getSalt() throws NoSuchAlgorithmException
    String encrypt(String text)
    String decrypt(String cypherText)
    String hash(String data)
}
