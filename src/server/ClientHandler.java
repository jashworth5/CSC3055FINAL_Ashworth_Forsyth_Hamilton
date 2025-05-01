package server;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;


public class ClientHandler implements Runnable {
    private final Socket socket;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))
        ) {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println("[Server] Received: " + line);
                out.write("ACK: " + line + "\n");
                out.flush();
            }
        } catch (IOException e) {
            System.err.println("[Handler] Error: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {}
            System.out.println("[Server] Client disconnected.");
        }
    }
}

