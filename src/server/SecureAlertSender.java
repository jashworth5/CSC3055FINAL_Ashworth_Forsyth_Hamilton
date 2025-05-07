package server;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.security.MessageDigest;

public class SecureAlertSender {

    private static final File ALERT_LOG = new File("logs/secure_alert_log.txt");

    public static void sendAlert(String message) {
        try {
            ALERT_LOG.getParentFile().mkdirs();
            String timestamp = Instant.now().toString();
            String fullMessage = "[" + timestamp + "] ALERT: " + message;

            String prevHash = "0";
            if (ALERT_LOG.exists()) {
                String lastLine = null;
                try (var reader = new java.io.BufferedReader(new java.io.FileReader(ALERT_LOG))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        lastLine = line;
                    }
                }
                if (lastLine != null && lastLine.contains("||")) {
                    prevHash = lastLine.split("\\|\\|")[1];
                }
            }

            String combined = fullMessage + prevHash;
            String hash = computeHash(combined);

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(ALERT_LOG, true))) {
                writer.write(fullMessage + "||" + hash + "\n");
            }

            System.out.println("[SecureAlertSender] Logged alert: " + fullMessage);

        } catch (IOException e) {
            System.err.println("[SecureAlertSender] Failed to write alert: " + e.getMessage());
        }
    }

    private static String computeHash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return "error_hashing";
        }
    }
}
