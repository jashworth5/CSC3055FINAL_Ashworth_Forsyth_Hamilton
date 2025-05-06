package client;

import java.util.List;
import java.util.Map;

public class PortAnalyzer {

    private static final int HIGH_PORT_THRESHOLD = 1024; // example criteria

    public PortAnalyzer() {
        // Initialize any state or load config here
    }

    /**
     * Entry point to analyze raw port data from the scanner.
     * @param portData List of parsed port entries from PortScanner
     */
    public void analyze(List<PortEntry> portData) {
        if (portData == null || portData.isEmpty()) {
            System.out.println("[Analyzer] No port data to analyze.");
            return;
        }

        detectUnusualActivity(portData);
        detectUnauthorizedPorts(portData);
        detectPortFlood(portData);
    }

    /**
     * Detects if a flood of ports (e.g., too many new ports opened quickly) is occurring.
     */
    private void detectPortFlood(List<PortEntry> entries) {
        // TODO: Check if more than N ports were opened in M seconds
    }

    /**
     * Compares active ports to a whitelist of allowed ports.
     */
    private void detectUnauthorizedPorts(List<PortEntry> entries) {
        // TODO: Load from config and compare
    }

    /**
     * Flags activity like uncommon service ports, high-range ports, etc.
     */
    private void detectUnusualActivity(List<PortEntry> entries) {
        for (PortEntry entry : entries) {
            int port = entry.getPort();
            if (port > HIGH_PORT_THRESHOLD) {
                System.out.println("[Analyzer] High-numbered port in use: " + port);
                // TODO: Maybe flag or send alert via AlertSender
            }
        }
    }
}