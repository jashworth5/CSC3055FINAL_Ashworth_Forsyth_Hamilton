package client;

import java.io.*;

public class PortScanner {
    public static void scanOpenPorts() {
        String command = System.getProperty("os.name").toLowerCase().contains("win") ?
                         "netstat -an" : "lsof -i -P -n | grep LISTEN";

        try {
            Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            System.out.println("Listening Ports:");
            while ((line = reader.readLine()) != null) {
                System.out.println("  " + line);
            }
        } catch (IOException e) {
            System.err.println("Error running port detection: " + e.getMessage());
        }
    }
}
