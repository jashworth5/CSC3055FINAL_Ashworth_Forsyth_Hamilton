import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

public class ForkBombSim {

    public static void main(String[] args) {
        List<ServerSocket> sockets = new ArrayList<>();
        int basePort = 6000;

        System.out.println("Launching fork bomb simulator...");

        for (int i = 0; i < 10; i++) {
            int port = basePort + i;
            try {
                ServerSocket serverSocket = new ServerSocket(port);
                sockets.add(serverSocket);
                System.out.println("Listening on port: " + port);
            } catch (IOException e) {
                System.err.println("Failed to open port " + port + ": " + e.getMessage());
            }

            try {
                Thread.sleep(50); //  small delay to simulate rapid but staggered opening
            } catch (InterruptedException ignored) {}
        }

        System.out.println("All ports bound. Press Ctrl+C to terminate.");

        // Keep sockets open
        while (true) {
            try {
                Thread.sleep(10000);
            } catch (InterruptedException ignored) {}
        }
    }
}
