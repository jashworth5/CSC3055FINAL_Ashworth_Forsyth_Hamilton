package server;

import client.PortEntry;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FileReader;
import java.util.*;

import org.json.JSONTokener;

public class PortAnalyzer {

    private final Set<Integer> whitelistedPorts = new HashSet<>();
    private final Set<String> whitelistedProcesses = new HashSet<>();
    private final Set<Integer> blacklistedPorts = new HashSet<>();
    private final Set<String> blacklistedProcesses = new HashSet<>();

    public PortAnalyzer() {
        loadRules("config/whitelist.json", whitelistedPorts, whitelistedProcesses);
        loadRules("config/blacklist.json", blacklistedPorts, blacklistedProcesses);
    }

    private void loadRules(String path, Set<Integer> portSet, Set<String> processSet) {
        try (FileReader reader = new FileReader(path)) {
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

    public JSONObject analyzeAndGroup(List<PortEntry> ports) {
        JSONArray whitelistArray = new JSONArray();
        JSONArray suspiciousArray = new JSONArray();
        JSONArray blacklistArray = new JSONArray();

        for (PortEntry entry : ports) {
            int port = entry.getPort();
            String process = entry.getProcess().toLowerCase();
            JSONObject jsonEntry = new JSONObject()
                    .put("port", port)
                    .put("protocol", entry.getProtocol())
                    .put("process", entry.getProcess());

            if (blacklistedPorts.contains(port) || blacklistedProcesses.contains(process)) {
                blacklistArray.put(jsonEntry);
                SecureAlertSender.sendAlert("CODE RED: " + port + " (" + entry.getProtocol() + ") by " + entry.getProcess());
            } else if (whitelistedPorts.contains(port) || whitelistedProcesses.stream().anyMatch(process::contains)) {
                whitelistArray.put(jsonEntry);
            } else {
                suspiciousArray.put(jsonEntry);
                SecureAlertSender.sendAlert("SUSPICIOUS: " + port + " (" + entry.getProtocol() + ") by " + entry.getProcess());
            }
        }

        JSONObject grouped = new JSONObject();
        grouped.put("whitelisted", whitelistArray);
        grouped.put("suspicious", suspiciousArray);
        grouped.put("blacklisted", blacklistArray);
        return grouped;
    }
}
