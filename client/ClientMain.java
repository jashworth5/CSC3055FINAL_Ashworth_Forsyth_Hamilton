package client;

import org.json.JSONObject;
import shared.TOTPUtil;
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
            // Authentication phase
            System.out.print("Welcome! Please enter your username: ");
            String username = scanner.nextLine();
            System.out.print("Password: ");
            String password = scanner.nextLine();
            output.println("LOGIN:" + username + ":" + password);

            String authResponse = input.readLine();
            if (authResponse == null || !authResponse.contains("successful")) {
                System.out.println("Server: Authentication failed or no response.");
                return;
            }

            System.out.println("Server: " + authResponse);

            // Generate and retrieve session key
            SessionKeyManager.generateSessionKey(); // Set it
            SecretKey sessionKey = SessionKeyManager.getSessionKey(); // Get it

            // Create alert
            Map<String, String> alert = new HashMap<>();
            alert.put("timestamp", String.valueOf(System.currentTimeMillis()));
            alert.put("event_type", "PORT_SCAN_DETECTED");
            alert.put("details", "Detected >20 port connections in 5 seconds");
            alert.put("nonce", "abc123");

            // Add HMAC
            String hmac = MessageEncryptor.computeHMAC(alert, sessionKey);
            alert.put("hmac", hmac);

            // Encrypt and send
            String jsonAlert = new JSONObject(alert).toString();
            String encryptedAlert = MessageEncryptor.encrypt(jsonAlert, sessionKey);
            output.println(encryptedAlert);

            System.out.println("Alert sent securely to server.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}