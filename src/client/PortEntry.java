package client;

import java.time.Instant;

/**
 * Represents a single parsed open port entry.
 */
public class PortEntry {
    private final int port;
    private final String protocol;  // e.g., TCP or UDP
    private final String process;
    private final String rawLine;   // original line from lsof or netstat, for debugging
    private final Instant timestamp; // timestamp of when the entry was created

    public PortEntry(int port, String protocol, String process, String rawLine) {
        this.port = port;
        this.protocol = protocol;
        this.process = process;
        this.rawLine = rawLine;
        this.timestamp = Instant.now();
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getProcess() {
        return process;
    }

    public String getRawLine() {
        return rawLine;
    }

    public Instant getTimestamp() { 
        return timestamp; 
    } 

    @Override
    public String toString() {
        return String.format("Port %d (%s) - %s", port, protocol, process);
    }
}