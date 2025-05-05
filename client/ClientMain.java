package client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Base64;

public class ClientMain {
    public static void main(String[] args) {
        System.out.println("Client started.");

        try (
            Socket socket = new Socket("localhost", 9999);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in))
        ) {
            System.out.println(input.readLine()); // Welcome!
            System.out.print("Username: ");
            String username = userInput.readLine();
            output.println(username);

            String challengeLine = input.readLine();
            String challenge = challengeLine.split(":")[1];

            System.out.print("Password: ");
            String password = userInput.readLine();

            String combined = challenge + password;
            String hashed = hashSHA256(combined);
            output.println(hashed);

            System.out.println("Server: " + input.readLine());
            System.out.println("Server: " + input.readLine());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String hashSHA256(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedBytes = digest.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }
}
