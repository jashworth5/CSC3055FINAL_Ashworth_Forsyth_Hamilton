package server;

import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

public class MessageEncryptor {

    private static final int GCM_IV_LENGTH = 12;    // 12 bytes = 96 bits
    private static final int GCM_TAG_LENGTH = 128;  // in bits

    //AES-GCM Encryption
    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Prepend IV to ciphertext
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return Base64.getEncoder().encodeToString(buffer.array());
    }

    // AES-GCM Decryption
    public static String decrypt(String encryptedBase64, SecretKey key) throws Exception {
        byte[] input = Base64.getDecoder().decode(encryptedBase64);
        ByteBuffer buffer = ByteBuffer.wrap(input);

        byte[] iv = new byte[GCM_IV_LENGTH];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // Compute HMAC (SHA-256) over JSON map
    public static String computeHMAC(Map<String, String> fields, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        // Create a canonical string representation of fields
        StringBuilder sb = new StringBuilder();
        fields.keySet().stream().sorted().forEach(k -> {
            sb.append(k).append("=").append(fields.get(k)).append("&");
        });

        byte[] hmacBytes = mac.doFinal(sb.toString().getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : hmacBytes) hex.append(String.format("%02x", b));
        return hex.toString();
    }

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256); // AES-256
        return generator.generateKey();
    }
}
