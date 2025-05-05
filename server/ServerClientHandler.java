package server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ServerClientHandler implements Runnable {
    private final Socket clientSocket;

    public ServerClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        try (
            BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter output = new PrintWriter(clientSocket.getOutputStream(), true)
        ) {
            output.println("Welcome to the secure server!");

            String message;
            while ((message = input.readLine()) != null) {
                System.out.println("Received: " + message);
                output.println("Echo: " + message);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (Exception ignored) {}
        }
    }
}
