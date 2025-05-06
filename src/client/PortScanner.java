package client;

import java.io.*;
import java.util.*;
import java.util.regex.*;

public class PortScanner {

    public static List<PortEntry> scanOpenPorts() {
        List<PortEntry> entries = new ArrayList<>();
        String os = System.getProperty("os.name").toLowerCase();
        String command = os.contains("win") ? "netstat -an" : "lsof -i -P -n | grep LISTEN";

        try {
            Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", command});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = reader.readLine()) != null) {
                PortEntry entry = parseLine(line);
                if (entry != null) {
                    entries.add(entry);
                }
            }
        } catch (IOException e) {
            System.err.println("[PortScanner] Error: " + e.getMessage());
        }

        return entries;
    }

    private static PortEntry parseLine(String line) {
        
        Pattern pattern = Pattern.compile("^(\\S+)\\s+\\d+\\s+\\S+\\s+\\d+u\\s+\\S+\\s+\\S+\\s+\\S+\\s+(TCP|UDP)\\s+\\S+:(\\d+)");
        Matcher matcher = pattern.matcher(line);

        if (matcher.find()) {
            String process = matcher.group(1);
            String protocol = matcher.group(2);
            int port = Integer.parseInt(matcher.group(3));
            return new PortEntry(port, protocol, process, line);
        }

        return null;
    }
}


