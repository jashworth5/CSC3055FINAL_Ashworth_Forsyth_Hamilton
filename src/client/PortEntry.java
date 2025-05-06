package client;

/**
 * Represents a single parsed open port entry.
 */
public class PortEntry {
    private final int port;
    private final String protocol;  // e.g., TCP or UDP
    private final String processName;
    private final String rawLine;   // original line from lsof or netstat, for debugging

    public PortEntry(int port, String protocol, String processName, String rawLine) {
        this.port = port;
        this.protocol = protocol;
        this.processName = processName;
        this.rawLine = rawLine;
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getProcessName() {
        return processName;
    }

    public String getRawLine() {
        return rawLine;
    }

    @Override
    public String toString() {
        return String.format("Port %d (%s) - %s", port, protocol, processName);
    }
}