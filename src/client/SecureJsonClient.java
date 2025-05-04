package client;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class SecureJsonClient {

    public static void main(String[] args) {
        try {
            // Load client configuration
            JSONObject config = JsonIO.readObject(new File("config/client_config.json"));

            String serverIp = config.get("server_ip").toString();
            int serverPort = ((Number) config.get("server_port")).intValue();
            String clientId = config.get("client_id").toString();
            String sharedSecret = config.get("shared_hmac_key").toString();

            try (
                Socket socket = new Socket(serverIp, serverPort);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                Scanner scanner = new Scanner(System.in)
            ) {
                System.out.println("[Client] Connected to server at " + serverIp + ":" + serverPort);

                while (true) {
                    System.out.print("[Client] Enter alert message (or 'exit'): ");
                    String message = scanner.nextLine();
                    if (message.equalsIgnoreCase("exit")) break;

                    String timestamp = Instant.now().toString();
                    String data = clientId + message + timestamp;
                    String hmac = computeHMAC(data, sharedSecret);

                    // Construct valid JSON manually
                    String jsonString = String.format(
                        "{\"client_id\":\"%s\",\"message\":\"%s\",\"timestamp\":\"%s\",\"hmac\":\"%s\"}",
                        escape(clientId), escape(message), escape(timestamp), escape(hmac)
                    );

                    System.out.println("[Debug] Sending JSON: " + jsonString);
                    out.write(jsonString + "\n");
                    out.flush();

                    String response = in.readLine();
                    System.out.println("[Client] Server response: " + response);
                }
            }

        } catch (Exception e) {
            System.err.println("[Client] Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // HMAC generator
    private static String computeHMAC(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hmacBytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("HMAC calculation failed", e);
        }
    }

    // Escapes double quotes inside strings to keep JSON valid
    private static String escape(String input) {
        return input.replace("\"", "\\\"");
    }
}
