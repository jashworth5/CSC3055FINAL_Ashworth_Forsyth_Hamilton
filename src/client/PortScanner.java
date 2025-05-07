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
            pb = new ProcessBuilder("cmd.exe", "/c", "netstat -ano");
        } else {
            pb = new ProcessBuilder("/bin/sh", "-c", "lsof -i -P -n | grep LISTEN");
        }

        try {
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            Map<String, String> pidToProcess = os.contains("win") ? getWindowsPidMap() : null;

            while ((line = reader.readLine()) != null) {
                PortEntry entry = os.contains("win") ? parseWindowsLine(line, pidToProcess) : parseUnixLine(line);
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

    private static PortEntry parseWindowsLine(String line, Map<String, String> pidMap) {
        if (!line.contains("LISTENING")) return null;

        String[] tokens = line.trim().split("\\s+");
        if (tokens.length < 5) return null;

        String protocol = tokens[0];
        String localAddress = tokens[1];
        String pid = tokens[tokens.length - 1];

        try {
            String[] parts = localAddress.split(":");
            int port = Integer.parseInt(parts[parts.length - 1]);
            String processName = pidMap.getOrDefault(pid, "PID:" + pid);
            return new PortEntry(port, protocol, processName, line);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Map<String, String> getWindowsPidMap() {
        Map<String, String> map = new HashMap<>();
        try {
            Process tasklist = new ProcessBuilder("cmd.exe", "/c", "tasklist /fo csv /nh").start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(tasklist.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\",\"");
                if (parts.length >= 2) {
                    String name = parts[0].replaceAll("\"", "").trim();
                    String pid = parts[1].replaceAll("\"", "").trim();
                    map.put(pid, name);
                }
            }
        } catch (IOException e) {
            System.err.println("[PortScanner] Could not get PID map: " + e.getMessage());
        }
        return map;
    }
}

