/**
 *
 * @author Bushra
 */
package crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MD5 {
    public static String hash(String data, String key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hashBytes = mac.doFinal(data.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String data = "Hello, World!";
        String key = "mySecretKey";
        String hash = hash(data, key);
        System.out.println("HMAC-SHA256 Hash: " + hash);
    }
}
