package server;

import org.json.JSONObject;
import utils.TOTPValidator;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class ServerClientHandler implements Runnable {
    private final Socket socket;
    private String username;

    private static final CHAPAuthenticator chap = new CHAPAuthenticator();
    private static final TOTPValidator totpValidator = new TOTPValidator("JBSWY3DPEHPK3PXP"); // test secret
    private static final File LOG_FILE = new File("logs/secure_log.txt");
    private static final File PORT_LOG_FILE = new File("logs/port_scan_log.txt");
    private static final NonceTracker nonceTracker = new NonceTracker();

    public ServerClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))
        ) {
            String line = in.readLine();
            if (line == null || !line.startsWith("USERNAME:")) {
                out.write("ERROR: Expected USERNAME\n"); out.flush(); return;
            }
            username = line.substring(9).trim();

            String challenge = chap.generateChallenge(username);
            out.write(challenge + "\n"); out.flush();

            line = in.readLine();
            if (line == null || !line.startsWith("RESPONSE:")) {
                out.write("ERROR: Expected RESPONSE\n"); out.flush(); return;
            }

            String[] parts = line.split(":", 3);
            if (parts.length != 3 || !parts[1].equals(username)) {
                out.write("ERROR: Malformed RESPONSE\n"); out.flush(); return;
            }

            String clientHash = parts[2];
            if (!chap.verifyResponse(username, clientHash)) {
                out.write("ERROR: Authentication failed\n"); out.flush(); return;
            }

            out.write("Authentication successful\n"); out.flush();

            line = in.readLine();
            if (line == null || !line.startsWith("TOTP:")) {
                out.write("ERROR: Expected TOTP\n"); out.flush(); return;
            }

            String totpCode = line.substring(5).trim();
            if (!totpValidator.validateCode(totpCode)) {
                out.write("ERROR: TOTP verification failed\n"); out.flush(); return;
            }

            out.write("TOTP verified\n"); out.flush();

            SessionKeyManager.generateSessionKey(username);
            SecretKey key = SessionKeyManager.getSessionKey(username);
            String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
            out.write("SESSIONKEY:" + encodedKey + "\n");
            out.flush();

            String encrypted;
            while ((encrypted = in.readLine()) != null) {
                if (encrypted.isEmpty()) continue;

                String decrypted = MessageEncryptor.decrypt(encrypted, key);
                JSONObject json = new JSONObject(decrypted);

                String nonce = json.optString("nonce");
                if (nonce == null || nonce.isEmpty()) {
                    String response = MessageEncryptor.encrypt("ERROR: Missing nonce", key);
                    out.write(response + "\n"); out.flush();
                    continue;
                }
                if (nonceTracker.isNonceUsed(nonce)) {
                    String response = MessageEncryptor.encrypt("ERROR: Nonce already used", key);
                    out.write(response + "\n"); out.flush();
                    continue;
                }
                nonceTracker.addNonce(nonce);

                String receivedHmac = json.getString("hmac");
                json.remove("hmac");

                Map<String, String> forHmac = new HashMap<>();
                forHmac.put("client_id", json.optString("client_id"));
                forHmac.put("timestamp", json.optString("timestamp"));
                forHmac.put("nonce", nonce);
                forHmac.put("ports", json.optJSONArray("ports").toString());

                String computedHmac = MessageEncryptor.computeHMAC(forHmac, key);
                if (!receivedHmac.equals(computedHmac)) {
                    String response = MessageEncryptor.encrypt("ERROR: Invalid HMAC", key);
                    out.write(response + "\n"); out.flush();
                    continue;
                }

                String eventType = json.optString("event_type");
                if ("PORT_SCAN_RESULT".equals(eventType)) {
                    String ports = json.optString("ports", "No port data provided.");
                    System.out.println("[Server] PORT SCAN REPORT from " + username + ":\n" + ports);

                    String[] lines = ports.split("\n");
                    Set<String> trustedPorts = Set.of("22", "80", "443", "3306");
                    Set<String> trustedProcesses = Set.of("sshd", "nginx", "httpd", "mysqld");

                    List<String> suspicious = new ArrayList<>();
                    for (String portLine : lines) {
                        boolean trusted = trustedPorts.stream().anyMatch(portLine::contains) &&
                                          trustedProcesses.stream().anyMatch(p -> portLine.toLowerCase().contains(p));
                        if (!trusted) suspicious.add(portLine);
                    }

                    String verdictMessage = suspicious.isEmpty() ?
                        "Ports OK" :
                        "⚠ Suspicious ports detected:\n" + String.join("\n", suspicious);

                    JSONObject verdict = new JSONObject();
                    verdict.put("verdict", verdictMessage);
                    String encryptedResponse = MessageEncryptor.encrypt(verdict.toString(), key);
                    out.write(encryptedResponse + "\n"); out.flush();

                    logPortScanSecure(username, ports, verdictMessage);
                } else {
                    String ackMessage = "Alert received securely";
                    String encryptedAck = MessageEncryptor.encrypt(ackMessage, key);
                    out.write(encryptedAck + "\n"); out.flush();
                    System.out.println("[Server] Secure alert from " + username + ": " + decrypted);
                    logSecure(decrypted);
                }
            }

        } catch (Exception e) {
            System.err.println("[Server] Handler error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private static Map<String, String> toStringMap(Map<String, Object> input) {
        Map<String, String> output = new HashMap<>();
        for (Map.Entry<String, Object> entry : input.entrySet()) {
            output.put(entry.getKey(), String.valueOf(entry.getValue()));
        }
        return output;
    }

    private void logSecure(String message) throws Exception {
        LOG_FILE.getParentFile().mkdirs();
        String prevHash = "0";

        if (LOG_FILE.exists()) {
            String last = null;
            try (BufferedReader r = new BufferedReader(new FileReader(LOG_FILE))) {
                String line;
                while ((line = r.readLine()) != null) last = line;
            }
            if (last != null && last.contains("||")) {
                prevHash = last.split("\\|\\|")[1];
            }
        }

        String combined = message + prevHash;
        String newHash = hash(combined);

        try (BufferedWriter w = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            w.write(message + "||" + newHash + "\n");
        }
    }

    private void logPortScanSecure(String username, String report, String verdict) throws Exception {
        PORT_LOG_FILE.getParentFile().mkdirs();
        String prevHash = "0";

        if (PORT_LOG_FILE.exists()) {
            String last = null;
            try (BufferedReader r = new BufferedReader(new FileReader(PORT_LOG_FILE))) {
                String line;
                while ((line = r.readLine()) != null) last = line;
            }
            if (last != null && last.contains("||")) {
                prevHash = last.split("\\|\\|")[1];
            }
        }

        String timestamp = java.time.Instant.now().toString();
        String entry = username + "::" + timestamp + "::" + verdict + "::" + report.replaceAll("\n", " | ");
        String combined = entry + prevHash;
        String newHash = hash(combined);

        try (BufferedWriter w = new BufferedWriter(new FileWriter(PORT_LOG_FILE, true))) {
            w.write(entry + "||" + newHash + "\n");
        }
    }

    private String hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(input.getBytes(StandardCharsets.UTF_8)));
    }
}
