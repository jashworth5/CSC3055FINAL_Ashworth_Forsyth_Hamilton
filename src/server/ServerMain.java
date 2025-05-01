package server;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;

public class ServerMain {
    private static final int PORT = 9000;
    private static final int MAX_CLIENTS = 10;
    private static final ExecutorService pool = Executors.newFixedThreadPool(MAX_CLIENTS);

    public static void main(String[] args) {
        System.out.println("🔐 [Server] Starting server on port " + PORT + "...");

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("✅ [Server] Client connected: " + clientSocket.getInetAddress());
                pool.execute(new ClientHandler(clientSocket));
            }
        } catch (IOException e) {
            System.err.println("❌ [Server] Error: " + e.getMessage());
        }
    }

}