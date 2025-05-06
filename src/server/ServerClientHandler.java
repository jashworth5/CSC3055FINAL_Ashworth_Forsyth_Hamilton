package server;

import org.json.JSONObject;
import utils.TOTPValidator;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class ServerClientHandler implements Runnable {
    private final Socket clientSocket;
    private static final HashSet<String> seenNonces = new HashSet<>();
    private static String previousLogHash = "";
    private static final CHAPAuthenticator auth = new CHAPAuthenticator();

    // Hardcoded user TOTP secrets (replace with secure storage in real use)
    private static final Map<String, String> totpSecrets = new HashMap<>();
    static {
        totpSecrets.put("alice", "JBSWY3DPEHPK3PXP");  // Base32 secret for alice
        totpSecrets.put("bob", "KZQXGIDCMFZWK3TQ");    // Another user (optional)
    }

    public ServerClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        try (
            BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter output = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            System.out.println("New client connected: " + clientSocket.getRemoteSocketAddress());

            // Step 1: Receive USERNAME
            String usernameMsg = input.readLine();
            if (usernameMsg == null || !usernameMsg.startsWith("USERNAME:")) {
                output.println("Invalid initial message.");
                return;
            }
            String username = usernameMsg.substring("USERNAME:".length());

            // Step 2: Send challenge
            String challenge = auth.generateChallenge(username);
            output.println(challenge);

            // Step 3: Receive response hash
            String response = input.readLine();
            if (response == null || !response.startsWith("RESPONSE:")) {
                output.println("Invalid response.");
                return;
            }

            String[] parts = response.split(":");
            if (parts.length != 3) {
                output.println("Invalid response format.");
                return;
            }

            String responseUser = parts[1];
            String clientHash = parts[2];

            // Step 4: Verify password challenge-response
            boolean valid = auth.verifyResponse(responseUser, clientHash);
            if (!valid) {
                output.println("Authentication failed!");
                return;
            }

            output.println("Authentication successful!");

            // Step 5: TOTP Verification
            String totpMsg = input.readLine();
            if (totpMsg == null || !totpMsg.startsWith("TOTP:")) {
                output.println("Invalid TOTP message.");
                return;
            }

            String totpCode = totpMsg.substring("TOTP:".length());
            String userSecret = totpSecrets.get(username);
            if (userSecret == null) {
                output.println("No TOTP secret found.");
                return;
            }

            TOTPValidator totpValidator = new TOTPValidator(userSecret);
            boolean totpValid = totpValidator.validateCode(totpCode);

            if (!totpValid) {
                output.println("TOTP verification failed.");
                return;
            }

            output.println("TOTP verified!");

            // Step 6: Receive encrypted alert
            String encryptedMessage = input.readLine();
            if (encryptedMessage == null) {
                System.out.println("No encrypted message received.");
                return;
            }

            System.out.println("Encrypted message received: " + encryptedMessage);

            SessionKeyManager.generateSessionKey();
            SecretKey sessionKey = SessionKeyManager.getSessionKey();
            String json = MessageEncryptor.decrypt(encryptedMessage, sessionKey);
            System.out.println("Decrypted message: " + json);

            JSONObject alert = new JSONObject(json);

            // Step 7: Nonce protection
            String nonce = alert.getString("nonce");
            if (!isFresh(nonce)) {
                System.out.println("Replayed alert blocked (nonce reused).");
                return;
            }

            // Step 8: Log alert with chained hash
            logAlert(alert.toString());
            System.out.println("Logged alert: " + alert);

        } catch (Exception e) {
            System.out.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private boolean isFresh(String nonce) {
        synchronized (seenNonces) {
            if (seenNonces.contains(nonce)) return false;
            seenNonces.add(nonce);
            return true;
        }
    }

    private void logAlert(String alert) {
        try {
            String combined = previousLogHash + alert;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined.getBytes());
            previousLogHash = bytesToHex(hash);

            try (FileWriter writer = new FileWriter("alert_log.txt", true)) {
                writer.write("Hash: " + previousLogHash + "\n");
                writer.write("Alert: " + alert + "\n\n");
            }
        } catch (Exception e) {
            System.out.println("Logging error: " + e.getMessage());
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
