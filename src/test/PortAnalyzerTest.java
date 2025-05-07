package test;

import client.PortEntry;
import server.PortAnalyzer;

import java.util.ArrayList;
import java.util.List;

public class PortAnalyzerTest {
    public static void main(String[] args) {
        List<PortEntry> mockPorts = new ArrayList<>();

        // Simulate various test cases
        mockPorts.add(new PortEntry(8080, "TCP", "unknownApp.exe", "raw line 1"));  // high port + unknown
        mockPorts.add(new PortEntry(9999, "TCP", "java", "raw line 2"));             // allowed port/process
        mockPorts.add(new PortEntry(3307, "TCP", "customMySQL", "raw line 3"));      // unlisted process
        mockPorts.add(new PortEntry(12345, "TCP", "hackerTool", "raw line 4"));      // suspicious

        // Simulate port flood
        for (int i = 4000; i < 4020; i++) {
            mockPorts.add(new PortEntry(i, "TCP", "tempService", "flood line" + i));
        }

        PortAnalyzer analyzer = new PortAnalyzer();
        analyzer.analyze(mockPorts);
    }
}
