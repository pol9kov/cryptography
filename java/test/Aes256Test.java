import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class Aes256Test {
    protected byte[] encrypt(byte[] plaintext, byte[] pass) throws Exception {
        return Aes256.encrypt(plaintext, pass);
    }

    protected String encrypt(String plaintext, String pass) throws Exception {
        return Aes256.encrypt(plaintext, pass);
    }

    protected byte[] decrypt(byte[] encrypted, byte[] pass) throws Exception {
        return Aes256.decrypt(encrypted, pass);
    }

    protected String decrypt(String encrypted, String pass) throws Exception {
        return Aes256.decrypt(encrypted, pass);
    }

    private void testDecrypt(String encrypted, String pass, String expect) {
        String result = "";
        byte[] bytes = new byte[0];

        try {
            result = decrypt(encrypted, pass);
        } catch (Exception e) {
        }

        try {
            bytes = decrypt(encrypted.getBytes(UTF_8), pass.getBytes(UTF_8));
        } catch (Exception e) {
        }

        assertEquals(expect, result, "Fail strings");
        assertArrayEquals(expect.getBytes(UTF_8), bytes, "Fail bytes");
    }

    private void testEncryptDecrypt(String plaintext, String pass) {
        String result = "";
        byte[] bytes = new byte[0];

        try {
            result = decrypt(encrypt(plaintext, pass), pass);
        } catch (Exception e) {
        }

        try {
            bytes = decrypt(encrypt(plaintext.getBytes(UTF_8), pass.getBytes(UTF_8)), pass.getBytes(UTF_8));
        } catch (Exception e) {
        }

        assertEquals(plaintext, result, "Fail strings");
        assertArrayEquals(plaintext.getBytes(UTF_8), bytes, "Fail bytes");
    }

    @Test
    public void testDecrypt() throws Exception {
        testDecrypt(
                "U2FsdGVkX1+Z9xSlpZGuO2zo51XUtsCGZPs8bKQ/jYg=",
                "pass",
                "test");
    }

    @Test
    public void testDecryptSpecialSymbols() {
        testDecrypt(
                "U2FsdGVkX18z+AAtII5UURkNCVtXllxir5sL+dmEUmjhTM6jzaY651xVDFAieQpgXUyh/bCtlPFm2snn/32kOx2hrR6NS5Xrow4OKHUbwS0=",
                "哈罗 こんにちわ Акїў 😺",
                "{\"Д\": \"@#$%^&*( 🤡👌 哈罗 こんにちわ Акїў\"}");
    }

    @Test
    public void testEncryptDecrypt1() {
        testEncryptDecrypt(
                "123123123",
                "asd");
    }

    @Test
    public void testEncryptDecryptSpecialSymbols() {
        testEncryptDecrypt(
                "{\"Д\": \"@#$%^&*( 🤡👌 哈罗 こんにちわ Акїў\"}",
                "哈罗 こんにちわ Акїў 😺");
    }
}
