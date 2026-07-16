
/**
 *
 * @author Bushra
 */
package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AES {
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16;

    public static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        // Prepend IV to ciphertext so decrypt can recover it
        byte[] ivAndCiphertext = new byte[IV_SIZE + encryptedData.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_SIZE);
        System.arraycopy(encryptedData, 0, ivAndCiphertext, IV_SIZE, encryptedData.length);
        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    public static String decrypt(String encryptedData, SecretKey key) throws Exception {
        byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedData);
        // Extract IV from the first 16 bytes
        byte[] iv = new byte[IV_SIZE];
        byte[] ciphertext = new byte[ivAndCiphertext.length - IV_SIZE];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_SIZE);
        System.arraycopy(ivAndCiphertext, IV_SIZE, ciphertext, 0, ciphertext.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedData = cipher.doFinal(ciphertext);
        return new String(decryptedData);
    }

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        String data = "Hello, World!";
        String encryptedData = encrypt(data, key);
        System.out.println("Encrypted: " + encryptedData);

        String decryptedData = decrypt(encryptedData, key);
        System.out.println("Decrypted: " + decryptedData);
    }
}
