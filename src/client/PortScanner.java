package client;

import java.io.*;
import java.util.*;
import java.util.regex.*;

public class PortScanner {

    public static List<PortEntry> scanOpenPorts() {
        List<PortEntry> entries = new ArrayList<>();
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder pb;

        if (os.contains("win")) {
            // Use Windows netstat
            pb = new ProcessBuilder("cmd.exe", "/c", "netstat -ano");
        } else {
            // Use lsof on Unix/Linux/macOS
            pb = new ProcessBuilder("/bin/sh", "-c", "lsof -i -P -n | grep LISTEN");
        }

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = reader.readLine()) != null) {
                PortEntry entry = os.contains("win") ? parseWindowsLine(line) : parseUnixLine(line);
                if (entry != null) {
                    entries.add(entry);
                }
            }

        } catch (IOException e) {
            System.err.println("[PortScanner] Error: " + e.getMessage());
        }

        return entries;
    }

    private static PortEntry parseUnixLine(String line) {
        // Typical lsof line format: process pid ... TCP *:8080 (LISTEN)
        Pattern pattern = Pattern.compile("^(\\S+)\\s+\\d+.*?(TCP|UDP)\\s+\\S+:(\\d+)");
        Matcher matcher = pattern.matcher(line);

        if (matcher.find()) {
            String process = matcher.group(1);
            String protocol = matcher.group(2);
            int port = Integer.parseInt(matcher.group(3));
            return new PortEntry(port, protocol, process, line);
        }

        return null;
    }

    private static PortEntry parseWindowsLine(String line) {
        if (!line.contains("LISTENING")) return null;

        String[] tokens = line.trim().split("\\s+");
        if (tokens.length < 5) return null;

        String protocol = tokens[0];
        String localAddress = tokens[1];
        String pid = tokens[tokens.length - 1];

        try {
            String[] parts = localAddress.split(":");
            int port = Integer.parseInt(parts[parts.length - 1]);
            return new PortEntry(port, protocol, "PID:" + pid, line);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
