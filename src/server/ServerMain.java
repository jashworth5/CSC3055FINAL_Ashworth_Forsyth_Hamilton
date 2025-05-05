package server;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

public class ServerMain {
    public static void main(String[] args) {
        try {
            String configText = Files.readString(Paths.get("config/server_config.json"));
            JSONObject config = JsonIO.readObject(configText);

            int port = ((Number) config.get("server_port")).intValue();
            int maxClients = ((Number) config.get("max_clients")).intValue();

            List<String> allowedClients = new ArrayList<>();
            JSONArray arr = (JSONArray) config.get("allowed_clients");
            for (int i = 0; i < arr.size(); i++) {
                allowedClients.add(arr.get(i).toString());
            }

            System.out.println("[Server] Starting server on port " + port + "...");
            ExecutorService pool = Executors.newFixedThreadPool(maxClients);

            try (ServerSocket serverSocket = new ServerSocket(port)) {
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    String clientIP = clientSocket.getInetAddress().getHostAddress();

                    if (!allowedClients.contains(clientIP)) {
                        System.out.println("[Server] Connection rejected from " + clientIP);
                        clientSocket.close();
                        continue;
                    }

                    System.out.println("[Server] Client connected: " + clientIP);
                    pool.execute(new ClientHandler(clientSocket));
                }
            }
        } catch (Exception e) {
            System.err.println("[Server] Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
