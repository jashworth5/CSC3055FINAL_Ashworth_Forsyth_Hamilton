package client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientMain {
    public static void main(String[] args) {
        System.out.println("Client started.");

        try (
            Socket socket = new Socket("localhost", 9999);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true)
        ) {
            System.out.println("Connected to server.");
            output.println("Hello from client!");
            String response = input.readLine();
            System.out.println("Server response: " + response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
