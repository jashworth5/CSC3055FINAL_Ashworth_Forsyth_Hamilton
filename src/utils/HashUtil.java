package utils;

import java.security.MessageDigest;
import java.util.Base64;

public class HashUtil {
    public static String hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(digest);  // match server
        } catch (Exception e) {
            throw new RuntimeException("Error generating hash", e);
        }
    }
}
