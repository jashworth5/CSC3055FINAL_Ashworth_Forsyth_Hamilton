package client;

import org.json.JSONArray;
import org.json.JSONObject;
import server.MessageEncryptor;
import client.PortEntry;
import client.PortScanner;
import server.SessionKeyManager;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.io.*;
import java.time.Instant;
import java.util.*;

public class PortReporter {

    private static final File REPORT_LOG = new File("logs/port_report_log.txt");

    public static void sendPortReport(String clientId, BufferedWriter out, BufferedReader in, JTextArea logArea) {
        try {
            List<PortEntry> openPorts = PortScanner.scanOpenPorts();
            JSONArray portsArray = new JSONArray();

            for (PortEntry port : openPorts) {
                JSONObject portJson = new JSONObject();
                portJson.put("port", port.getPort());
                portJson.put("protocol", port.getProtocol());
                portJson.put("process", port.getProcess());
                portsArray.put(portJson);
            }

            String timestamp = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();

            JSONObject payload = new JSONObject();
            payload.put("client_id", clientId);
            payload.put("timestamp", timestamp);
            payload.put("nonce", nonce);
            payload.put("ports", portsArray);
            payload.put("event_type", "PORT_SCAN_RESULT");

            SecretKey sessionKey = SessionKeyManager.getSessionKey(clientId);
            Map<String, String> forHmac = new HashMap<>();
            forHmac.put("client_id", clientId);
            forHmac.put("timestamp", timestamp);
            forHmac.put("nonce", nonce);
            forHmac.put("ports", portsArray.toString());
            String hmac = MessageEncryptor.computeHMAC(forHmac, sessionKey);
            payload.put("hmac", hmac);

            String encrypted = MessageEncryptor.encrypt(payload.toString(), sessionKey);
            out.write(encrypted + "\n");
            out.flush();

            logArea.append("[PortReporter] Sent port report to server.\n");
            logPortReport(clientId, timestamp, portsArray.toString());

            String response = in.readLine();
            if (response != null && !response.trim().isEmpty()) {
                String decrypted = MessageEncryptor.decrypt(response, sessionKey);
                JSONObject json = new JSONObject(decrypted);

                logArea.append("\n=== Port Scan Analysis ===\n\n");

                logArea.append("🟢 Whitelisted:\n");
                for (Object obj : json.optJSONArray("whitelisted")) {
                    JSONObject entry = (JSONObject) obj;
                    logArea.append(" - Port " + entry.getInt("port") + " (" +
                            entry.getString("protocol") + ") - " +
                            entry.getString("process") + "\n");
                }
                logArea.append("\n");

                logArea.append("🟡 Suspicious:\n");
                for (Object obj : json.optJSONArray("suspicious")) {
                    JSONObject entry = (JSONObject) obj;
                    logArea.append(" - Port " + entry.getInt("port") + " (" +
                            entry.getString("protocol") + ") - " +
                            entry.getString("process") + "\n");
                }
                logArea.append("\n");

                logArea.append("🔴 Blacklisted:\n");
                for (Object obj : json.optJSONArray("blacklisted")) {
                    JSONObject entry = (JSONObject) obj;
                    int port = entry.getInt("port");
                    String protocol = entry.getString("protocol");
                    String process = entry.getString("process");

                    logArea.append(" - Port " + port + " (" + protocol + ") - " + process + "\n");
                    logArea.append(" ⚠️  WARNING: Process '" + process + "' on port " + port + " should be terminated immediately.\n\n");
                }

                logArea.append("\n===========================\n\n");
            }



        } catch (Exception e) {
            logArea.append("[PortReporter] Failed to send port report: " + e.getMessage() + "\n");
        }
    }

    private static void logPortReport(String clientId, String timestamp, String ports) {
        try {
            REPORT_LOG.getParentFile().mkdirs();
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(REPORT_LOG, true))) {
                writer.write("[" + timestamp + "] " + clientId + " PORT REPORT:\n" + ports + "\n\n");
            }
        } catch (IOException e) {
            System.err.println("[PortReporter] Failed to write to port report log: " + e.getMessage());
        }
    }
}
