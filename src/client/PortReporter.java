package client;

import server.MessageEncryptor;
import server.SessionKeyManager;

import javax.crypto.SecretKey;
import java.io.BufferedWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class PortReporter {

    public static void sendPortReport(String clientId, BufferedWriter out) {
        try {
            List<PortEntry> openPorts = PortScanner.scanOpenPorts();
    
            StringBuilder sb = new StringBuilder();
            for (PortEntry port : openPorts) {
                sb.append("Port ").append(port.getPort())
                  .append(" (").append(port.getProtocol()).append(")")
                  .append(" - ").append(port.getProcess())
                  .append("\n");
            }
    
            String report = sb.toString();
            String nonce = UUID.randomUUID().toString();
            String timestamp = java.time.Instant.now().toString();
    
            Map<String, String> payload = new HashMap<>();
            payload.put("client_id", clientId);
            payload.put("event_type", "PORT_SCAN_RESULT");
            payload.put("timestamp", timestamp);
            payload.put("ports", report);
            payload.put("nonce", nonce);
    
            SecretKey sessionKey = SessionKeyManager.getSessionKey(clientId);
            String hmac = MessageEncryptor.computeHMAC(payload, sessionKey);
            payload.put("hmac", hmac);
    
            String json = new org.json.JSONObject(payload).toString();
            String encrypted = MessageEncryptor.encrypt(json, sessionKey);
    
            out.write(encrypted + "\n");
            out.flush();
    
            System.out.println("[PortReporter] Sent port report to server.");
    
        } catch (Exception e) {
            System.err.println("[PortReporter] Failed to send port report: " + e.getMessage());
        }
    }
}

/**
 *  Port Reporting Protocol Overview
 *
 *  Updated Plan for Client-Server Intrusion Detection:
 *
 * CLIENT SIDE:
 * - PortScanner gathers all TCP ports in LISTEN state.
 * - PortReporter collects the scanned ports, wraps them in a JSON object, HMAC signs, encrypts, and sends to the server.
 *
 * SERVER SIDE:
 * - Server decrypts the incoming port telemetry using the session key.
 * - Server parses the JSON into a port list.
 * - Server compares the list against a known-good whitelist OR runs heuristics to detect suspicious ports.
 * - Server builds a response: e.g., "Ports OK" or "Suspicious port 9999 used by unknown process".
 * - Server sends this back as a simple JSON verdict.
 *
 *  ROUND-TRIP FLOW:
 * 1. Client scans ports and builds a structured report.
 * 2. Client signs and encrypts report, sends it to server.
 * 3. Server decrypts and inspects the report.
 * 4. Server generates a response verdict (e.g. warning or approval).
 * 5. Server sends the verdict back to the client.
 * 6. Client displays the server verdict in the GUI or logs it.
 *
 * 
 */