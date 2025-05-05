package server;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.IOException;

public class Server {
    private static final int PORT = 9999; // You can replace with config value later

    public static void main(String[] args) {
        System.out.println("Server is running on port " + PORT);

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected: " + clientSocket.getInetAddress());

                // Start a new thread with the correct handler
                new Thread(new ServerClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
