package client;

import server.CHAPAuthenticator;
import server.MessageEncryptor;
import server.SessionKeyManager;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

import org.json.JSONTokener;
import org.json.JSONObject;
import org.json.JSONArray;

import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;


public class ClientGUI extends JFrame {

    private CardLayout cardLayout = new CardLayout();
    private JPanel mainPanel = new JPanel(cardLayout);

    private JTextField usernameField = new JTextField(15);
    private JPasswordField passwordField = new JPasswordField(15);
    private JTextField totpField = new JTextField(6);

    private JTextField alertField = new JTextField(30);
    private JTextArea logArea = new JTextArea(15, 40);

    private static final File LOG_FILE = new File("client-secure-log.txt");
    private static final File LOGIN_HISTORY_FILE = new File("logs/login_history.txt");

    private Socket socket;
    private BufferedReader in;
    private BufferedWriter out;
    private SecretKey sessionKey;

    public ClientGUI() {
        setTitle("Client");
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        JPanel loginScreen = createLoginScreen();
        JPanel alertScreen = createAlertScreen();

        mainPanel.add(loginScreen, "login");
        mainPanel.add(alertScreen, "alert");

        add(mainPanel);
        cardLayout.show(mainPanel, "login");

        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private JPanel createLoginScreen() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        JLabel title = new JLabel("Login to Secure Client", JLabel.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 18));
        panel.add(title, BorderLayout.NORTH);

        gbc.gridx = 0; gbc.gridy = 0; form.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; form.add(usernameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; form.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1; form.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; form.add(new JLabel("TOTP Code:"), gbc);
        gbc.gridx = 1; form.add(totpField, gbc);

        JButton loginButton = new JButton("Login");
        loginButton.addActionListener(e -> handleLogin());
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        form.add(loginButton, gbc);

        panel.add(form, BorderLayout.CENTER);
        return panel;
    }

    private void showPorts() {
        List<PortEntry> ports = PortScanner.scanOpenPorts();
        log("Open Ports:");
        for (PortEntry entry : ports) {
            log(" - " + entry.toString());
        }
        if (ports.isEmpty()) {
            log("No listening ports detected.");
        }
    }

    private JPanel createAlertScreen() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        JLabel header = new JLabel("Port Scan Dashboard", JLabel.CENTER);
        header.setFont(new Font("Arial", Font.BOLD, 16));
        panel.add(header, BorderLayout.NORTH);

        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(logArea);
        panel.add(scroll, BorderLayout.CENTER);

        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new FlowLayout());

        JButton scanButton = new JButton("Scan Ports");
        scanButton.addActionListener(e -> showPorts());
        inputPanel.add(scanButton);

        JButton portScanButton = new JButton("Send Port Report");
        portScanButton.addActionListener(e -> 
            PortReporter.sendPortReport(usernameField.getText().trim(), out, in, logArea)
        );
        inputPanel.add(portScanButton);

        JButton whitelistButton = new JButton("Add to Whitelist");
        whitelistButton.addActionListener(e -> promptWhitelistEntry());
        inputPanel.add(whitelistButton);

        JButton blacklistButton = new JButton("Add to Blacklist");
        blacklistButton.addActionListener(e -> promptBlacklistEntry());
        inputPanel.add(blacklistButton);

        panel.add(inputPanel, BorderLayout.SOUTH);
        return panel;
    }

    private void handleLogin() {
        String username = usernameField.getText().trim();
        String totp = totpField.getText().trim();

        if (username.isEmpty() || totp.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please fill in all fields.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int attempts = 0;
        boolean success = false;

        while (attempts < 3 && !success) {
            String password = new String(passwordField.getPassword()).trim();
            attempts++;

            try {
                socket = new Socket("127.0.0.1", 9999);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

                out.write("USERNAME:" + username + "\n");
                out.flush();

                String challenge = in.readLine();
                String responseHash = CHAPAuthenticator.hashChallenge(challenge, password);
                out.write("RESPONSE:" + username + ":" + responseHash + "\n");
                out.flush();

                String authReply = in.readLine();
                if (!authReply.contains("successful")) {
                    log("Server: " + authReply);
                    socket.close();
                    logLoginAttempt(username, false);
                    continue;
                }

                out.write("TOTP:" + totp + "\n");
                out.flush();

                String totpReply = in.readLine();
                if (!totpReply.contains("verified")) {
                    log("Server: " + totpReply);
                    socket.close();
                    logLoginAttempt(username, false);
                    continue;
                }

                String keyLine = in.readLine();
                if (keyLine == null || !keyLine.startsWith("SESSIONKEY:")) {
                    log("Failed to receive session key.");
                    socket.close();
                    logLoginAttempt(username, false);
                    continue;
                }

                byte[] decoded = Base64.getDecoder().decode(keyLine.substring(11).trim());
                sessionKey = new SecretKeySpec(decoded, 0, decoded.length, "AES");
                SessionKeyManager.setSessionKey(username, sessionKey);

                String lastLogin = findLastSuccessfulLogin(username);
                if (lastLogin != null) {
                    log("Last successful login: " + lastLogin);
                }


                log("Login successful. You can now send secure alerts.");
                logLoginAttempt(username, true);
                cardLayout.show(mainPanel, "alert");
                success = true;
            } catch (Exception ex) {
                log("Login error: " + ex.getMessage());
                logLoginAttempt(username, false);
            }
        }

        if (!success) {
            JOptionPane.showMessageDialog(this, "Login failed after 3 attempts.", "Login Failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void sendAlert() {
        String message = alertField.getText().trim();
        if (message.isEmpty()) return;

        try {
            String timestamp = Instant.now().toString();
            String nonce = UUID.randomUUID().toString();
            Map<String, String> alert = new HashMap<>();
            alert.put("client_id", usernameField.getText().trim());
            alert.put("message", message);
            alert.put("timestamp", timestamp);
            alert.put("nonce", nonce);

            String hmac = MessageEncryptor.computeHMAC(alert, sessionKey);
            alert.put("hmac", hmac);

            String json = new org.json.JSONObject(alert).toString();
            String encrypted = MessageEncryptor.encrypt(json, sessionKey);

            out.write(encrypted + "\n");
            out.flush();

            String response = in.readLine();
            log("Server: " + response);
            logSecure(message);
            alertField.setText("");
        } catch (Exception ex) {
            log("Error: " + ex.getMessage());
        }
    }

    private void log(String msg) {
        logArea.append(msg + "\n");
    }

    private void logSecure(String message) throws Exception {
        String prevHash = "0";

        if (LOG_FILE.exists()) {
            String last = null;
            try (BufferedReader r = new BufferedReader(new FileReader(LOG_FILE))) {
                String line;
                while ((line = r.readLine()) != null) last = line;
            }
            if (last != null && last.contains("||")) {
                prevHash = last.split("\\|\\|")[1];
            }
        }

        String combined = message + prevHash;
        String newHash = hash(combined);

        try (BufferedWriter w = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            w.write(message + "||" + newHash + "\n");
        }
    }

    private String findLastSuccessfulLogin(String username) {
        if (!LOGIN_HISTORY_FILE.exists()) return null;
    
        List<String> successLines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(LOGIN_HISTORY_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(username + " - SUCCESS")) {
                    successLines.add(line);
                }
            }
        } catch (IOException e) {
            return null;
        }
    
        if (successLines.size() < 2) {
            return "This is your first successful login.";
        } else {
            // Second to last successful login
            String rawTimestamp = successLines.get(successLines.size() - 2).split(" - ")[0];
            try {
                Instant instant = Instant.parse(rawTimestamp);
                ZonedDateTime zdt = instant.atZone(ZoneId.systemDefault());
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
                return zdt.format(formatter);
            } catch (Exception e) {
                return rawTimestamp; // fallback
            }
        }
    }
    

    private void addToWhitelist(int port, String process) {
    File file = new File("config/whitelist.json");

    try {
        JSONObject data;
        if (file.exists()) {
            try (FileReader reader = new FileReader(file)) {
                data = new JSONObject(new JSONTokener(reader));
            }
        } else {
            data = new JSONObject();
            data.put("ports", new JSONArray());
            data.put("processes", new JSONArray());
        }

        JSONArray ports = data.optJSONArray("ports");
        JSONArray processes = data.optJSONArray("processes");

        if (port >= 0 && !ports.toList().contains(port)) {
            ports.put(port);
        }

        if (process != null && !processes.toList().contains(process.toLowerCase())) {
            processes.put(process.toLowerCase());
        }

        try (FileWriter writer = new FileWriter(file)) {
            writer.write(data.toString(4)); // Pretty print
        }

        JOptionPane.showMessageDialog(this, "Whitelist updated.", "Success", JOptionPane.INFORMATION_MESSAGE);
    } catch (Exception e) {
        JOptionPane.showMessageDialog(this, "Failed to update whitelist:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
    }
}


    private void promptWhitelistEntry() {
        String[] options = {"Port", "Process"};
        int choice = JOptionPane.showOptionDialog(
            this,
            "What would you like to whitelist?",
            "Add to Whitelist",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]
        );
    
        if (choice == 0) { // Port
            String input = JOptionPane.showInputDialog(this, "Enter port number:");
            try {
                int port = Integer.parseInt(input.trim());
                addToWhitelist(port, null);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "Invalid port number.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else if (choice == 1) { // Process
            String input = JOptionPane.showInputDialog(this, "Enter process name:");
            if (input != null && !input.trim().isEmpty()) {
                addToWhitelist(-1, input.trim());
            }
        }
    }

    private void addToBlacklist(int port, String process) {
        File file = new File("config/blacklist.json");
    
        try {
            JSONObject data;
            if (file.exists()) {
                try (FileReader reader = new FileReader(file)) {
                    data = new JSONObject(new JSONTokener(reader));
                }
            } else {
                data = new JSONObject();
                data.put("ports", new JSONArray());
                data.put("processes", new JSONArray());
            }
    
            JSONArray ports = data.optJSONArray("ports");
            JSONArray processes = data.optJSONArray("processes");
    
            if (port >= 0 && !ports.toList().contains(port)) {
                ports.put(port);
            }
    
            if (process != null && !processes.toList().contains(process.toLowerCase())) {
                processes.put(process.toLowerCase());
            }
    
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(data.toString(4)); // Pretty print
            }
    
            JOptionPane.showMessageDialog(this, "Blacklist updated.", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Failed to update blacklist:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    

    private void promptBlacklistEntry() {
        String[] options = {"Port", "Process"};
        int choice = JOptionPane.showOptionDialog(
            this,
            "What would you like to blacklist?",
            "Add to Blacklist",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]
        );
    
        if (choice == 0) { // Port
            String input = JOptionPane.showInputDialog(this, "Enter port number:");
            try {
                int port = Integer.parseInt(input.trim());
                addToBlacklist(port, null);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "Invalid port number.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else if (choice == 1) { // Process
            String input = JOptionPane.showInputDialog(this, "Enter process name:");
            if (input != null && !input.trim().isEmpty()) {
                addToBlacklist(-1, input.trim());
            }
        }
    }
    
    private void logLoginAttempt(String username, boolean success) {
        String timestamp = Instant.now().toString();
        String status = success ? "SUCCESS" : "FAILURE";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOGIN_HISTORY_FILE, true))) {
            writer.write(timestamp + " - " + username + " - " + status + "\n");
        } catch (IOException e) {
            log("Failed to write login history.");
        }
    }

    private String hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(ClientGUI::new);
    }
}
