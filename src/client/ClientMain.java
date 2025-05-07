package client;

import server.MessageEncryptor;
import server.SessionKeyManager;
import server.CHAPAuthenticator;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.time.Instant;
import java.util.*;

public class ClientMain {

    public static void main(String[] args) {
        try (
            Socket socket = new Socket("127.0.0.1", 9999);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            Scanner scanner = new Scanner(System.in)
        ) {
            System.out.println("Client started.");

            // Step 1: Send username
            System.out.print("Welcome! Please enter your username: ");
            String username = scanner.nextLine();

            out.write("USERNAME:" + username + "\n");
            out.flush();

            String challenge = in.readLine();
            if (challenge == null || challenge.trim().isEmpty()) {
                System.err.println("Failed to receive challenge. Exiting.");
                return;
            }

            // Step 2: Try password authentication
            boolean authenticated = false;
            for (int attempts = 0; attempts <= 3; attempts++) {
                System.out.print("Password: ");
                String password = scanner.nextLine();

                String responseHash = CHAPAuthenticator.hashChallenge(challenge, password);
                out.write("RESPONSE:" + username + ":" + responseHash + "\n");
                out.flush();

                String authReply = in.readLine();
                if (authReply == null) {
                    System.out.println("Server closed the connection. Exiting.");
                    return;
                }

                System.out.println("Server: " + authReply);
                if (authReply.contains("successful")) {
                    authenticated = true;
                    break;
                }
            }

            if (!authenticated) {
                System.out.println("Too many failed attempts. Disconnecting.");
                return;
            }

            // Step 3: TOTP Verification
            System.out.print("Enter your TOTP code: ");
            String totp = scanner.nextLine();
            out.write("TOTP:" + totp + "\n");
            out.flush();

            String totpReply = in.readLine();
            if (totpReply == null) {
                System.out.println("Server closed the connection after TOTP. Exiting.");
                return;
            }

            System.out.println("Server: " + totpReply);
            if (!totpReply.contains("verified")) return;

            // Step 4: Receive session key
            String keyLine = in.readLine();
            if (keyLine == null || !keyLine.startsWith("SESSIONKEY:")) {
                System.err.println("[Client] ERROR: No session key received");
                return;
            }

            String encodedKey = keyLine.substring(11).trim();
            byte[] decoded = Base64.getDecoder().decode(encodedKey);
            SecretKey sessionKey = new SecretKeySpec(decoded, 0, decoded.length, "AES");
            SessionKeyManager.setSessionKey(username, sessionKey);

            // Step 5: Action menu
            System.out.println("\n========= Client Action Menu =========");
            while (true) {
                System.out.println("\nSelect an action:");
                System.out.println("[1] Send custom alert");
                System.out.println("[2] Port scan (local only, print result)");
                System.out.println("[3] Port scan and report to server");
                System.out.println("[0] Exit");
                System.out.print("> ");
                String choice = scanner.nextLine();

                if (choice.equals("0")) {
                    System.out.println("[Client] Exiting...");
                    break;

                } else if (choice.equals("1")) {
                    System.out.print("Enter alert message: ");
                    String message = scanner.nextLine();

                    String timestamp = Instant.now().toString();
                    String nonce = UUID.randomUUID().toString();

                    Map<String, String> alert = new LinkedHashMap<>();
                    alert.put("client_id", username);
                    alert.put("message", message);
                    alert.put("timestamp", timestamp);
                    alert.put("nonce", nonce);

                    String hmac = MessageEncryptor.computeHMAC(alert, sessionKey);
                    alert.put("hmac", hmac);

                    String jsonString = new org.json.JSONObject(alert).toString();
                    String encrypted = MessageEncryptor.encrypt(jsonString, sessionKey);

                    out.write(encrypted + "\n");
                    out.flush();

                    String response = in.readLine();
                    System.out.println("[Server Response] " + response);

                } else if (choice.equals("2")) {
                    System.out.println("[Port Scan] Local results:");
                    List<PortEntry> ports = PortScanner.scanOpenPorts();
                    for (PortEntry port : ports) {
                        System.out.printf(" - Port %d (%s) - %s%n",
                            port.getPort(), port.getProtocol(), port.getProcess());
                    }

                } else if (choice.equals("3")) {
                    System.out.println("[Client] Starting port scan and sending encrypted report...");
                    PortReporter.sendPortReport(username, out, in, null);
                } else {
                    System.out.println("Invalid choice. Try again.");
                }
            }

            System.out.println("Disconnected from server.");

        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}