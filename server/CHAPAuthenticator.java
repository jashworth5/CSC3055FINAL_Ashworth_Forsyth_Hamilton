package server;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

public class CHAPAuthenticator {
    private final HashMap<String, String> userPasswords = new HashMap<>(); // username → password
    private final HashMap<String, String> activeChallenges = new HashMap<>();

    public CHAPAuthenticator() {
        // Demo credentials (should load from file/db in real use)
        userPasswords.put("alice", "password123");
        userPasswords.put("bob", "secure456");
    }

    public String generateChallenge(String username) {
        String challenge = String.valueOf(new Random().nextInt(999999));
        activeChallenges.put(username, challenge);
        return challenge;
    }

    // You can call this to get the expected hash server-side
    public String getExpectedHash(String username, String password) throws NoSuchAlgorithmException {
        String challenge = activeChallenges.get(username);
        if (challenge == null) return null;
        return hash(challenge + password);
    }

    public boolean verifyResponse(String username, String clientHash) {
        try {
            String password = userPasswords.get(username);
            String challenge = activeChallenges.get(username);

            if (password == null || challenge == null) return false;

            String expected = hash(challenge + password);
            return expected.equals(clientHash);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            activeChallenges.remove(username); // One-time challenge
        }
    }

    // Private utility
    private String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }
}