package client;

import org.json.JSONArray;
import org.json.JSONObject;
import server.MessageEncryptor;
import client.PortEntry;
import client.PortScanner;
import server.SessionKeyManager;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.time.Instant;
import java.util.*;

public class PortReporter {

    public static void sendPortReport(String clientId, BufferedWriter out, BufferedReader in, JTextArea logArea) {
        try {
            // 1. Scan open ports
            List<PortEntry> openPorts = PortScanner.scanOpenPorts();
            JSONArray portsArray = new JSONArray();

            for (PortEntry port : openPorts) {
                JSONObject portJson = new JSONObject();
                portJson.put("port", port.getPort());
                portJson.put("protocol", port.getProtocol());
                portJson.put("process", port.getProcess());
                portsArray.put(portJson);
            }

            // 2. Build top-level JSON structure
            String timestamp = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();

            JSONObject payload = new JSONObject();
            payload.put("client_id", clientId);
            payload.put("timestamp", timestamp);
            payload.put("nonce", nonce);
            payload.put("ports", portsArray);

            // 3. Compute HMAC
            SecretKey sessionKey = SessionKeyManager.getSessionKey(clientId);
            String hmac = MessageEncryptor.computeHMAC(toStringMap(payload), sessionKey);
            payload.put("hmac", hmac);

            // 4. Encrypt the full JSON
            String encrypted = MessageEncryptor.encrypt(payload.toString(), sessionKey);

            // 5. Send encrypted blob
            out.write(encrypted + "\n");
            out.flush();

            logArea.append("[PortReporter] Sent port report to server.\n");

            // 6. Handle server response
            String response = in.readLine();
            if (response != null && !response.trim().isEmpty()) {
                String verdict = MessageEncryptor.decrypt(response, sessionKey);
                logArea.append("[Server Verdict] " + verdict + "\n");
            }

        } catch (Exception e) {
            logArea.append("[PortReporter] Failed to send port report: " + e.getMessage() + "\n");
        }
    }

    // Helper to convert JSON to Map<String, String> for HMAC
    private static Map<String, String> toStringMap(JSONObject obj) {
        Map<String, String> result = new HashMap<>();
        for (String key : obj.keySet()) {
            Object value = obj.get(key);
            if (value instanceof JSONArray) {
                result.put(key, value.toString()); // flatten array as string for HMAC
            } else {
                result.put(key, String.valueOf(value));
            }
        }
        return result;
    }
}

