package server;

import client.PortEntry;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.File;
import java.io.FileReader;
import java.util.*;

public class PortAnalyzer {

    private final Set<Integer> whitelistedPorts = new HashSet<>();
    private final Set<String> whitelistedProcesses = new HashSet<>();
    private final Set<Integer> blacklistedPorts = new HashSet<>();
    private final Set<String> blacklistedProcesses = new HashSet<>();

    private final List<String> alerts = new ArrayList<>();

    public PortAnalyzer() {
        loadRules("config/whitelist.json", whitelistedPorts, whitelistedProcesses);
        loadRules("config/blacklist.json", blacklistedPorts, blacklistedProcesses);
    }

    private void loadRules(String path, Set<Integer> portSet, Set<String> processSet) {
        try (FileReader reader = new FileReader(new File(path))) {
            JSONObject obj = new JSONObject(new JSONTokener(reader));
            JSONArray ports = obj.optJSONArray("ports");
            JSONArray procs = obj.optJSONArray("processes");

            if (ports != null) {
                for (int i = 0; i < ports.length(); i++) {
                    portSet.add(ports.getInt(i));
                }
            }
            if (procs != null) {
                for (int i = 0; i < procs.length(); i++) {
                    processSet.add(procs.getString(i).toLowerCase());
                }
            }
        } catch (Exception e) {
            System.err.println("[Analyzer] Failed to load rules from " + path + ": " + e.getMessage());
        }
    }

    public String analyze(List<PortEntry> portData) {
        alerts.clear();
        if (portData == null || portData.isEmpty()) {
            alerts.add("No port data provided.");
            return formatReport();
        }
    
        Set<String> seen = new HashSet<>(); // avoid duplicates
    
        for (PortEntry entry : portData) {
            int port = entry.getPort();
            String process = entry.getProcess().toLowerCase();
            String key = port + "|" + process;
    
            if (!seen.add(key)) continue; // skip duplicates
    
            // Whitelist check — skip if port is whitelisted
            if (whitelistedPorts.contains(port)) continue;
    
            // Blacklist match
            if (blacklistedPorts.contains(port) || blacklistedProcesses.contains(process)) {
                String msg = "CODE RED: Blacklisted port/process detected: " +
                             port + " (" + entry.getProtocol() + ") by " + entry.getProcess();
                alerts.add(msg);
                SecureAlertSender.sendAlert(msg);
                continue;
            }
    
            // Suspicious
            if (whitelistedProcesses.stream().noneMatch(proc -> process.contains(proc))) {
                String msg = "** Suspicious port detected: " + port +
                             " (" + entry.getProtocol() + ") by " + entry.getProcess();
                alerts.add(msg);
                SecureAlertSender.sendAlert(msg);
            }
        }
    
        if (alerts.isEmpty()) {
            alerts.add("All ports and processes are within expected behavior.");
        }
    
        return formatReport();
    }

    private String formatReport() {
        return String.join("\n", alerts);
    }
}