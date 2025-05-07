package server;

import java.util.*;
import java.util.stream.Collectors;
import client.PortEntry;

public class PortAnalyzer {

    private static final int HIGH_PORT_THRESHOLD = 1024;
    private static final int PORT_FLOOD_THRESHOLD = 15; // number of ports
    private static final int TIME_WINDOW_SECONDS = 60;

    private final Set<Integer> allowedPorts = Set.of(22, 80, 443, 3306, 9999); // Add more as needed
    private final Set<String> allowedProcesses = Set.of("java", "mysqld", "nginx", "sshd", "httpd");

    public PortAnalyzer() {
        // Optionally load dynamic config here
    }

    public void analyze(List<PortEntry> portData) {
        if (portData == null || portData.isEmpty()) {
            System.out.println("[Analyzer] No port data to analyze.");
            return;
        }

        detectUnusualActivity(portData);
        detectUnauthorizedPorts(portData);
        detectPortFlood(portData);
    }

    private void detectUnusualActivity(List<PortEntry> entries) {
        for (PortEntry entry : entries) {
            if (entry.getPort() > HIGH_PORT_THRESHOLD) {
                String msg = "High-numbered port in use: " + entry.getPort() + " by " + entry.getProcess();
                System.out.println("[Analyzer] " + msg);
                SecureAlertSender.sendAlert(msg);
            }
        }
    }

    private void detectUnauthorizedPorts(List<PortEntry> entries) {
        for (PortEntry entry : entries) {
            if (!allowedPorts.contains(entry.getPort()) &&
                allowedProcesses.stream().noneMatch(proc -> entry.getProcess().toLowerCase().contains(proc))) {
                String msg = "Unauthorized port detected: " + entry.getPort() +
                             " (" + entry.getProtocol() + ") by " + entry.getProcess();
                System.out.println("[Analyzer] " + msg);
                SecureAlertSender.sendAlert(msg);
            }
        }
    }

    private void detectPortFlood(List<PortEntry> entries) {
        long currentTime = System.currentTimeMillis();
        Map<Integer, Long> portOpenTimes = new HashMap<>();

        for (PortEntry entry : entries) {
            portOpenTimes.put(entry.getPort(), currentTime); // Ideally use real timestamps if available
        }

        long count = portOpenTimes.values().stream()
                .filter(ts -> (currentTime - ts) <= TIME_WINDOW_SECONDS * 1000L)
                .count();

        if (count >= PORT_FLOOD_THRESHOLD) {
            String msg = "Potential port flood detected: " + count + " ports opened within last " + TIME_WINDOW_SECONDS + "s.";
            System.out.println("[Analyzer] " + msg);
            SecureAlertSender.sendAlert(msg);
        }
    }
}
