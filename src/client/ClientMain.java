package client;

import java.io.*;
import java.net.*;
import java.util.Scanner;

public class ClientMain {
    private static final String SERVER_IP = "127.0.0.1";
    private static final int SERVER_PORT = 9000;

    public static void main(String[] args) {
        try (
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            Scanner scanner = new Scanner(System.in)
        ) {
            System.out.println("[Client] Connected to server at " + SERVER_IP + ":" + SERVER_PORT);

            while (true) {
                System.out.print("[Client] Enter message (or 'exit'): ");
                String message = scanner.nextLine();
                if (message.equalsIgnoreCase("exit")) break;

                out.write(message + "\n");
                out.flush();

                String response = in.readLine();
                System.out.println("[Client] Server says: " + response);
            }

        } catch (IOException e) {
            System.err.println("[Client] Error: " + e.getMessage());
        }

        System.out.println("[Client] Disconnected.");
    }
}
