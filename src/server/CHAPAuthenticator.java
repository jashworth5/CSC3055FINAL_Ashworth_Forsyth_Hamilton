package server;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

public class CHAPAuthenticator {
    private final HashMap<String, String> userPasswords = new HashMap<>();
    private final HashMap<String, String> activeChallenges = new HashMap<>();

    public CHAPAuthenticator() {
        userPasswords.put("alice", "password123");
    }

    public String generateChallenge(String username) {
        String challenge = String.valueOf(new Random().nextInt(999999));
        activeChallenges.put(username, challenge);
        return challenge;
    }

    public boolean verifyResponse(String username, String clientHash) {
        try {
            String password = userPasswords.get(username);
            String challenge = activeChallenges.get(username);

            if (password == null || challenge == null) return false;

            String expected = hash(challenge + password);

            // TEMP DEBUG
            System.out.println("[CHAP] Challenge: " + challenge);
            System.out.println("[CHAP] Password: " + password);
            System.out.println("[CHAP] Expected: " + expected);
            System.out.println("[CHAP] Received: " + clientHash);

            return expected.equals(clientHash);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            activeChallenges.remove(username);
        }
    }

    private String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }
}
