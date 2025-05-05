package client;

import org.json.JSONObject;
import shared.HashUtil;
import server.MessageEncryptor;
import server.SessionKeyManager;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class ClientMain {
    public static void main(String[] args) {
        System.out.println("Client started.");

        try (
            Socket socket = new Socket("localhost", 9999);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
            Scanner scanner = new Scanner(System.in)
        ) {
            // Step 1: Send username
            System.out.print("Welcome! Please enter your username: ");
            String username = scanner.nextLine();
            output.println("USERNAME:" + username);

            // Step 2: Receive challenge
            String challenge = input.readLine();
            if (challenge == null || challenge.isEmpty()) {
                System.out.println("Server did not respond with a challenge.");
                return;
            }

            // Step 3: Password input and response
            System.out.print("Password: ");
            String password = scanner.nextLine();
            String responseHash = HashUtil.hash(challenge + password);
            output.println("RESPONSE:" + username + ":" + responseHash);

            // Step 4: Read password auth result
            String authResponse = input.readLine();
            if (authResponse == null || !authResponse.contains("successful")) {
                System.out.println("Server: Authentication failed or no response.");
                return;
            }
            System.out.println("Server: " + authResponse);

            // Step 5: Send TOTP code
            System.out.print("Enter your TOTP code: ");
            String totp = scanner.nextLine();
            output.println("TOTP:" + totp);

            // Step 6: Read TOTP response
            String totpResponse = input.readLine();
            if (totpResponse == null || !totpResponse.contains("TOTP verified")) {
                System.out.println("Server: TOTP verification failed.");
                return;
            }
            System.out.println("Server: " + totpResponse);

            // Step 7: Session key
            SessionKeyManager.generateSessionKey();
            SecretKey sessionKey = SessionKeyManager.getSessionKey();

            // Step 8: Create alert
            Map<String, String> alert = new HashMap<>();
            alert.put("timestamp", String.valueOf(System.currentTimeMillis()));
            alert.put("event_type", "PORT_SCAN_DETECTED");
            alert.put("details", "Detected >20 port connections in 5 seconds");
            alert.put("nonce", "abc123");

            // HMAC + encryption
            String hmac = MessageEncryptor.computeHMAC(alert, sessionKey);
            alert.put("hmac", hmac);

            String jsonAlert = new JSONObject(alert).toString();
            String encryptedAlert = MessageEncryptor.encrypt(jsonAlert, sessionKey);
            output.println(encryptedAlert);

            System.out.println("Alert sent securely to server.");

        } catch (Exception e) {
            System.out.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
