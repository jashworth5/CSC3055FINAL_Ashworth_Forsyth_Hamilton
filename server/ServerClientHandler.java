package server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ServerClientHandler implements Runnable {
    private final Socket clientSocket;
    private final CHAPAuthenticator authenticator = new CHAPAuthenticator();

    public ServerClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        try (
            BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter output = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            output.println("Welcome! Please enter your username:");
            String username = input.readLine();

            String challenge = authenticator.generateChallenge(username);
            output.println("CHALLENGE:" + challenge);

            String clientHash = input.readLine(); // this is hash(challenge + password)
            if (authenticator.verifyResponse(username, clientHash)) {
                output.println("Authentication successful!");
            } else {
                output.println("Authentication failed.");
                clientSocket.close();
                return;
            }

            // Continue with secure communication
            output.println("Welcome to the secure server!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
