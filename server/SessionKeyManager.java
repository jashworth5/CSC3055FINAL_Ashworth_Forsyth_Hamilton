package server;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SessionKeyManager {
    private static SecretKey sessionKey;

    public static void generateSessionKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // AES-256
            sessionKey = keyGen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey getSessionKey() {
        return sessionKey;
    }

    public static void setSessionKey(SecretKey key) {
        sessionKey = key;
    }
}
