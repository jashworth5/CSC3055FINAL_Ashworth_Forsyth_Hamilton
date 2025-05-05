package shared;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SessionKeyManager {
    private final HashMap<String, SecretKey> sessionKeys = new HashMap<>();

    // Generate and store a new session key for a given session ID
    public SecretKey generateSessionKey(String sessionId) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // AES-256
            SecretKey key = keyGen.generateKey();
            sessionKeys.put(sessionId, key);
            return key;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Retrieve an existing session key
    public SecretKey getSessionKey(String sessionId) {
        return sessionKeys.get(sessionId);
    }

    // Remove session key (e.g., on logout or expiration)
    public void removeSessionKey(String sessionId) {
        sessionKeys.remove(sessionId);
    }
}
