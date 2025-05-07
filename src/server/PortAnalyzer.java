package server;

import client.PortEntry;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FileReader;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

    private void detectForkBomb(List<PortEntry> entries, JSONObject groupedJson) {

        // Group timestamps
        Map<Instant, List<PortEntry>> bySecond = new HashMap<>();

        for (PortEntry e : entries) {
            Instant secondBucket = e.getTimestamp().truncatedTo(ChronoUnit.SECONDS);
            bySecond.computeIfAbsent(secondBucket, k -> new ArrayList<>()).add(e);
        }

        // Look for any second where >= 8 new unique ports started listening
        for (Map.Entry<Instant, List<PortEntry>> entry : bySecond.entrySet()) {
            long uniquePorts = entry.getValue().stream()
                .map(PortEntry::getPort)
                .distinct()
                .count();

            if (uniquePorts >= 8) {
                String msg = "⚠️  Potential fork bomb detected: " + uniquePorts +
                            " unique ports opened at " + entry.getKey().toString();
                groupedJson.put("forkbomb", msg);
                SecureAlertSender.sendAlert(msg);
                break;
            }
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
    
    
        // Build final result object
        JSONObject grouped = new JSONObject();
        grouped.put("whitelisted", whitelistArray);
        grouped.put("suspicious", suspiciousArray);
        grouped.put("blacklisted", blacklistArray);
    
        // Detect fork bomb
        detectForkBomb(ports, grouped);
    
        return grouped;
    }
    
}
