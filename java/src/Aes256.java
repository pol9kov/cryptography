import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;


public class Aes256 extends AbstractAes256 {

    public static void main(String[] args) throws Exception {
        System.out.println(encrypt("123123123", "asd"));
    }

    /**
     * Encrypt text with the passphrase
     *
     * @param plaintext Input text to encrypt
     * @param pass      The passphrase
     * @return A base64 encoded string containing the encrypted data
     * @throws Exception Throws exceptions
     */
    public static String encrypt(String plaintext, String pass) throws Exception {
        return Base64.getEncoder().encodeToString(_encrypt(plaintext.getBytes(UTF_8), pass.getBytes(UTF_8)));
    }

    /**
     * Encrypt text in bytes with the passphrase
     *
     * @param plaintext Input data in bytes to encrypt
     * @param pass      The passphrase in bytes
     * @return A base64 encoded bytes containing the encrypted data
     * @throws Exception Throws exceptions
     */
    public static byte[] encrypt(byte[] plaintext, byte[] pass) throws Exception {
        return Base64.getEncoder().encode(_encrypt(plaintext, pass));
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes
     *
     * @param encrypted Text in bytes to decrypt
     * @param pass      The passphrase in bytes
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    public static String decrypt(String encrypted, String pass) throws Exception {
        return new String(_decrypt(Base64.getDecoder().decode(encrypted), pass.getBytes(UTF_8)), UTF_8);
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes
     *
     * @param encrypted Text in bytes to decrypt
     * @param pass      The passphrase in bytes
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    public static byte[] decrypt(byte[] encrypted, byte[] pass) throws Exception {
        return _decrypt(Base64.getDecoder().decode(encrypted), pass);
    }
}
