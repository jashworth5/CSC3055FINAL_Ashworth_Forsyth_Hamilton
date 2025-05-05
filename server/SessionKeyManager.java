package server;

import java.util.HashMap;
import java.util.Map;

public class SessionKeyManager {

    private final Map<String, byte[]> sessionKeys = new HashMap<>();

    // Store a session key for a given username/client
    public void storeSessionKey(String username, byte[] key) {
        sessionKeys.put(username, key);
    }

    // Retrieve the session key for a given user
    public byte[] getSessionKey(String username) {
        return sessionKeys.get(username);
    }

    // Remove session key when client logs out or times out
    public void removeSessionKey(String username) {
        sessionKeys.remove(username);
    }

    // Check if key exists for a user
    public boolean hasSessionKey(String username) {
        return sessionKeys.containsKey(username);
    }
}
