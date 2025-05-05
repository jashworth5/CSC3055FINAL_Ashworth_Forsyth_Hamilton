package server;

import org.json.JSONObject;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.HashSet;

public class ServerClientHandler implements Runnable {
    private final Socket clientSocket;
    private static final HashSet<String> seenNonces = new HashSet<>();
    private static String previousLogHash = "";
    private static final CHAPAuthenticator auth = new CHAPAuthenticator();

    public ServerClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        try (
            BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter output = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            String message = input.readLine();
            System.out.println("Received: " + message);

            if (message != null && message.startsWith("LOGIN:")) {
                String[] parts = message.split(":");
                if (parts.length == 3) {
                    String username = parts[1];
                    String password = parts[2];

                    // Generate expected hash using new public method in CHAPAuthenticator
                    String expectedHash = auth.getExpectedHash(username, password);
                    boolean valid = auth.verifyResponse(username, expectedHash);

                    if (valid) {
                        output.println("Authentication successful!");
                        SessionKeyManager.generateSessionKey(); // store session key
                    } else {
                        output.println("Authentication failed!");
                        return;
                    }
                } else {
                    output.println("Invalid login format.");
                    return;
                }
            } else {
                output.println("Authentication failed!");
                return;
            }

            // After authentication: receive alert
            String encryptedMessage = input.readLine();
            SecretKey sessionKey = SessionKeyManager.getSessionKey();
            String json = MessageEncryptor.decrypt(encryptedMessage, sessionKey);
            JSONObject alert = new JSONObject(json);

            String nonce = alert.getString("nonce");
            if (!isFresh(nonce)) {
                System.out.println("Replayed alert blocked (nonce reused).");
                return;
            }

            System.out.println("Logging alert: " + alert.toString());
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

            try (FileWriter writer = new FileWriter("secure_log.txt", true)) {
                writer.write("Hash: " + previousLogHash + "\n");
                writer.write("Alert: " + alert + "\n\n");
            }
        } catch (Exception e) {
            System.out.println("Logging error: " + e.getMessage());
            e.printStackTrace();
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
