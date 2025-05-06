package server;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.concurrent.ConcurrentHashMap;

public class SessionKeyManager {
    private static final ConcurrentHashMap<String, SecretKey> sessionKeys = new ConcurrentHashMap<>();

    public static void generateSessionKey(String clientId) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // AES-256
            SecretKey key = keyGen.generateKey();
            sessionKeys.put(clientId, key);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey getSessionKey(String clientId) {
        return sessionKeys.get(clientId);
    }

    public static void setSessionKey(String clientId, SecretKey key) {
        sessionKeys.put(clientId, key);
    }

    public static void removeSessionKey(String clientId) {
        sessionKeys.remove(clientId);
    }
}
