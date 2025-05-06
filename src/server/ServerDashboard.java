package server;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Executors;

public class ServerDashboard extends JFrame {

    private JTextArea alertLog = new JTextArea(20, 50);
    private DefaultListModel<String> clientListModel = new DefaultListModel<>();
    private JList<String> clientList = new JList<>(clientListModel);

    public ServerDashboard() {
        setTitle("Server Dashboard");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        alertLog.setEditable(false);
        JScrollPane logScroll = new JScrollPane(alertLog);

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("Connected Clients"));
        leftPanel.add(new JScrollPane(clientList), BorderLayout.CENTER);

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBorder(BorderFactory.createTitledBorder("Incoming Alerts"));
        centerPanel.add(logScroll, BorderLayout.CENTER);

        add(leftPanel, BorderLayout.WEST);
        add(centerPanel, BorderLayout.CENTER);

        pack();
        setLocationRelativeTo(null);
        setVisible(true);

        Executors.newSingleThreadExecutor().execute(this::startServer);
    }

    private void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(9999)) {
            log("Server started on port 9999...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                String clientId = clientSocket.getInetAddress().getHostAddress();
                SwingUtilities.invokeLater(() -> clientListModel.addElement(clientId));

                new Thread(() -> handleClient(clientSocket, clientId)).start();
            }

        } catch (IOException e) {
            log("Server error: " + e.getMessage());
        }
    }

    private void handleClient(Socket socket, String clientId) {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))
        ) {
            String line;
            while ((line = in.readLine()) != null) {
                log("[" + clientId + "] " + line);
                out.write("Alert received\n");
                out.flush();
            }

        } catch (IOException e) {
            log("Connection error with " + clientId + ": " + e.getMessage());
        } finally {
            SwingUtilities.invokeLater(() -> clientListModel.removeElement(clientId));
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private void log(String message) {
        SwingUtilities.invokeLater(() -> alertLog.append(message + "\n"));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(ServerDashboard::new);
    }
}
