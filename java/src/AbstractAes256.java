import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;


public abstract class AbstractAes256 {
    protected static final byte[] SALTED = "Salted__".getBytes(US_ASCII);

    /**
     * Internal encrypt function
     *
     * @param plaintext Input text to encrypt
     * @param pass      The pass
     * @return Encrypted data
     * @throws Exception Throws exceptions
     */
    protected static byte[] _encrypt(byte[] plaintext, byte[] pass) throws Exception {
        byte[] salt = (new SecureRandom()).generateSeed(8);
        Object[] keyIv = deriveKeyAndIv(pass, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec((byte[]) keyIv[0], "AES"), new IvParameterSpec((byte[]) keyIv[1]));

        byte[] enc = cipher.doFinal(plaintext);
        return concat(concat(SALTED, salt), enc);
    }

    /**
     * Internal decrypt function
     *
     * @param encrypted Text in bytes to decrypt
     * @param pass      The passphrase
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    protected static byte[] _decrypt(byte[] encrypted, byte[] pass) throws Exception {
        byte[] salt = Arrays.copyOfRange(encrypted, 8, 16);

        if (!Arrays.equals(Arrays.copyOfRange(encrypted, 0, 8), SALTED)) {
            throw new IllegalArgumentException("Invalid crypted data");
        }

        Object[] keyIv = deriveKeyAndIv(pass, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec((byte[]) keyIv[0], "AES"), new IvParameterSpec((byte[]) keyIv[1]));
        return cipher.doFinal(encrypted, 16, encrypted.length - 16);
    }

    /**
     * Derive key and iv
     *
     * @param pass Passphrase
     * @param salt Salt
     * @return Array of key and iv
     * @throws Exception Throws exceptions
     */
    protected static Object[] deriveKeyAndIv(byte[] pass, byte[] salt) throws Exception {
        final MessageDigest md5 = MessageDigest.getInstance("MD5");
        final byte[] passSalt = concat(pass, salt);
        byte[] dx = new byte[0];
        byte[] di = new byte[0];

        for (int i = 0; i < 3; i++) {
            di = md5.digest(concat(di, passSalt));
            dx = concat(dx, di);
        }

        return new Object[]{Arrays.copyOfRange(dx, 0, 32), Arrays.copyOfRange(dx, 32, 48)};
    }

    /**
     * Concatenate bytes
     *
     * @param a First array
     * @param b Second array
     * @return Concatenated bytes
     */
    protected static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
