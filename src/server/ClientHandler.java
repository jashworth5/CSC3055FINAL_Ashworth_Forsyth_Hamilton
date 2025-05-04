package server;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.*;

public class ClientHandler implements Runnable {

    private final Socket socket;
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String SHARED_SECRET = "verysecretkey";
    private static final Path LOG_PATH = Paths.get("logs/alert_log.txt");

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))
        ) {
            String line;
            while ((line = in.readLine()) != null) {
                try {
                    JSONType root = JsonIO.readObject(line);

                    if (root == null || !(root instanceof JSONObject json)) {
                        out.write("ERROR: Invalid message format\n");
                        out.flush();
                        continue;
                    }

                    String clientId = json.get("client_id").toString();
                    String message = json.get("message").toString();
                    String timestamp = json.get("timestamp").toString();
                    String receivedHmac = json.get("hmac").toString();

                    // Reconstruct and verify HMAC
                    String data = clientId + message + timestamp;
                    String computedHmac = computeHMAC(data, SHARED_SECRET);

                    if (!computedHmac.equals(receivedHmac)) {
                        out.write("ERROR: Invalid HMAC\n");
                        out.flush();
                        System.out.println("[Security] Rejected message from " + clientId);
                        continue;
                    }

                    String logEntry = clientId + "|" + timestamp + "|" + message;
                    appendLogWithHash(logEntry);

                    out.write("ACK: Message received\n");
                    out.flush();
                    System.out.println("[Server] Logged alert from " + clientId);

                } catch (Exception ex) {
                    out.write("ERROR: Invalid message format\n");
                    out.flush();
                    ex.printStackTrace();
                }
            }
        } catch (IOException e) {
            System.err.println("[Handler] Error: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {}
            System.out.println("[Server] Client disconnected.");
        }
    }

    private String computeHMAC(String data, String key) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_ALGO);
        mac.init(secretKey);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hmacBytes);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private void appendLogWithHash(String entry) throws Exception {
        Files.createDirectories(LOG_PATH.getParent());

        String previousHash = "0";
        if (Files.exists(LOG_PATH)) {
            List<String> lines = Files.readAllLines(LOG_PATH);
            if (!lines.isEmpty()) {
                String lastLine = lines.get(lines.size() - 1);
                previousHash = lastLine.split("\\|\\|")[1];
            }
        }

        String newHash = computeSHA256(entry + previousHash);
        String fullLog = entry + "||" + newHash;

        Files.writeString(LOG_PATH, fullLog + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    private String computeSHA256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }
}
