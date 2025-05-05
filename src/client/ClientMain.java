package client;

import java.io.*;
import java.net.*;
import java.util.Scanner;

public class ClientMain {

    private static final String SERVER_IP = "127.0.0.1";
    private static final int SERVER_PORT = 9000;

    public static void main(String[] args) {

        // Detect operating system
        String os = System.getProperty("os.name").toLowerCase();
        System.out.println("[Client] Detected OS: " + os);

        // Scan open/listening ports
        scanOpenPorts(os);

        // Connect to server
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

    // Port scanner function
    private static void scanOpenPorts(String os) {
        String command;
        if (os.contains("win")) {
            command = "netstat -an";
        } else {
            command = "lsof -i -P -n | grep LISTEN";
        }

        System.out.println("[Client] Scanning open ports...");
        try {
            Process process = new ProcessBuilder("bash", "-c", command).start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("  " + line);
            }
        } catch (IOException e) {
            System.err.println("[Client] Port scan failed: " + e.getMessage());
        }
    }
}
