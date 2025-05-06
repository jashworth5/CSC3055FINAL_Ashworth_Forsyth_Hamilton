package server;

import org.json.JSONObject;
import utils.HashUtil;
import utils.TOTPValidator;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;

public class ServerClientHandler implements Runnable {
    private final Socket socket;
    private String username;

    private static final CHAPAuthenticator chap = new CHAPAuthenticator();
    private static final TOTPValidator totpValidator = new TOTPValidator("JBSWY3DPEHPK3PXP"); // test secret
    private static final File LOG_FILE = new File("logs/secure_log.txt");

    public ServerClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))
        ) {
            // Step 1: Username
            String line = in.readLine();
            if (line == null || !line.startsWith("USERNAME:")) {
                out.write("ERROR: Expected USERNAME\n"); out.flush(); return;
            }
            username = line.substring(9).trim();

            // Step 2: CHAP challenge
            String challenge = chap.generateChallenge(username);
            out.write(challenge + "\n"); out.flush();

            // Step 3: CHAP response
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

            // Step 4: TOTP verification
            line = in.readLine();
            if (line == null || !line.startsWith("TOTP:")) {
                out.write("ERROR: Expected TOTP\n"); out.flush(); return;
            }

            String totpCode = line.substring(5).trim();
            if (!totpValidator.validateCode(totpCode)) {
                out.write("ERROR: TOTP verification failed\n"); out.flush(); return;
            }

            out.write("TOTP verified\n"); out.flush();

            // Step 5: Setup session key
            SessionKeyManager.generateSessionKey(username);
            SecretKey key = SessionKeyManager.getSessionKey(username);

            // Step 6: Receive encrypted alert
            String encrypted = in.readLine();
            if (encrypted == null || encrypted.isEmpty()) {
                out.write("ERROR: No encrypted message\n"); out.flush(); return;
            }

            String decrypted = MessageEncryptor.decrypt(encrypted, key);
            JSONObject json = new JSONObject(decrypted);

            String receivedHmac = json.getString("hmac");
            json.remove("hmac");

            // ✅ Use helper method to convert map to Map<String, String>
            String computedHmac = MessageEncryptor.computeHMAC(toStringMap(json.toMap()), key);

            if (!receivedHmac.equals(computedHmac)) {
                out.write("ERROR: Invalid HMAC\n"); out.flush(); return;
            }

            out.write("Alert received securely\n"); out.flush();
            System.out.println("[Server] Secure alert from " + username + ": " + decrypted);
            logSecure(decrypted);

        } catch (Exception e) {
            System.err.println("[Server] Handler error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    // ✅ Helper to convert Map<String, Object> to Map<String, String>
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

    private String hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(input.getBytes()));
    }
}
