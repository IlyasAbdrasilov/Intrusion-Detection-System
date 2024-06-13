package IDS;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.io.File;
import java.sql.*;
import java.util.List;
import java.util.concurrent.TimeoutException;

import static IDS.PacketSniffer.*;

//класс реализации GUI
public class GUI {

    static void setupGUI() {
        mainFrame = new JFrame("Intrusion Detection System");
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        mainFrame.setSize(400, 600);
        mainFrame.setLayout(new BorderLayout());

        cardLayout = new CardLayout();
        mainPanel = new JPanel(cardLayout);

        JPanel loginPanel = createLoginPanel();
        JPanel registerPanel = createRegisterPanel();
        JPanel appPanel = createAppPanel();

        mainPanel.add(loginPanel, "Login");
        mainPanel.add(registerPanel, "Register");
        mainPanel.add(appPanel, "App");

        mainFrame.add(mainPanel);
        mainFrame.setVisible(true);

        // Show login panel initially
        cardLayout.show(mainPanel, "Login");
    }

    private static JPanel createRegisterPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(new Color(41, 50, 65));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel iconLabel = new JLabel();
        iconLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel userLabel = new JLabel("USERNAME:");
        userLabel.setForeground(Color.WHITE);
        JTextField userField = new JTextField(15);
        userField.setPreferredSize(new Dimension(200, 30));
        JLabel passLabel = new JLabel("PASSWORD:");
        passLabel.setForeground(Color.WHITE);
        JPasswordField passField = new JPasswordField(15);
        passField.setPreferredSize(new Dimension(200, 30));
        JLabel confirmPassLabel = new JLabel("CONFIRM PASSWORD:");
        confirmPassLabel.setForeground(Color.WHITE);
        JPasswordField confirmPassField = new JPasswordField(15);
        confirmPassField.setPreferredSize(new Dimension(200, 30));

        JButton registerButton = new JButton("SIGN UP");
        registerButton.setBackground(new Color(51, 153, 255));
        registerButton.setForeground(Color.WHITE);
        registerButton.setPreferredSize(new Dimension(200, 40));
        registerButton.setFocusPainted(false);

        JButton backButton = new JButton("BACK");
        backButton.setBackground(new Color(51, 153, 255));
        backButton.setForeground(Color.WHITE);
        backButton.setPreferredSize(new Dimension(200, 40));
        backButton.setFocusPainted(false);

        registerButton.addActionListener(e -> {
            String username = userField.getText();
            String password = new String(passField.getPassword());
            String confirmPassword = new String(confirmPassField.getPassword());
            if (password.equals(confirmPassword)) {
                if (registerUser(username, password)) {
                    JOptionPane.showMessageDialog(mainFrame, "Registration successful", "Success", JOptionPane.INFORMATION_MESSAGE);
                    cardLayout.show(mainPanel, "Login");
                } else {
                    JOptionPane.showMessageDialog(mainFrame, "Wrong Username or Password", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(mainFrame, "Passwords do not match", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        backButton.addActionListener(e -> {
            cardLayout.show(mainPanel, "Login");
        });

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(iconLabel, gbc);

        gbc.gridy = 1;
        panel.add(userLabel, gbc);

        gbc.gridy = 2;
        panel.add(userField, gbc);

        gbc.gridy = 3;
        panel.add(passLabel, gbc);

        gbc.gridy = 4;
        panel.add(passField, gbc);

        gbc.gridy = 5;
        panel.add(confirmPassLabel, gbc);

        gbc.gridy = 6;
        panel.add(confirmPassField, gbc);

        gbc.gridy = 7;
        panel.add(registerButton, gbc);

        gbc.gridy = 8;
        panel.add(backButton, gbc);

        return panel;
    }

    private static JPanel createAppPanel() {
        JPanel appPanel = new JPanel(new BorderLayout());

        textArea = new JTextArea();
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        DefaultCaret caret = (DefaultCaret) textArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BorderLayout());

        JLabel interfaceLabel = new JLabel("Select Network Interface:");
        JComboBox<PcapNetworkInterface> interfaceComboBox = new JComboBox<>();
        JButton startButton = new JButton("Start");
        JButton stopButton = new JButton("Stop");

        stopButton.setEnabled(false); // Disable stop button initially

        topPanel.add(interfaceLabel, BorderLayout.WEST);
        topPanel.add(interfaceComboBox, BorderLayout.CENTER);
        topPanel.add(startButton, BorderLayout.EAST);
        topPanel.add(stopButton, BorderLayout.SOUTH);

        appPanel.add(topPanel, BorderLayout.NORTH);
        appPanel.add(scrollPane, BorderLayout.CENTER);

        // Populate the combo box with available network interfaces
        try {
            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            for (PcapNetworkInterface dev : allDevs) {
                interfaceComboBox.addItem(dev);
            }
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }

        startButton.addActionListener(e -> {
            PcapNetworkInterface networkInterface = (PcapNetworkInterface) interfaceComboBox.getSelectedItem();
            if (networkInterface == null) {
                printToTextArea("No network interface selected.");
                return;
            }

            capturing = true;
            startButton.setEnabled(false);
            stopButton.setEnabled(true);

            // Start capturing packets on the selected interface
            new Thread(() -> {
                try {
                    int snapshotLength = 65536; // Max packet length to capture
                    int readTimeout = 10; // In milliseconds
                    handle = networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);

                    // Capture packets and process them
                    while (capturing) {
                        try {
                            Packet packet = handle.getNextPacketEx();
                            processPacket(packet);
                        } catch (TimeoutException ex) {
                            // Ignore timeout exceptions
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                    }
                } catch (PcapNativeException ex) {
                    ex.printStackTrace();
                } finally {
                    if (handle != null && handle.isOpen()) {
                        handle.close();
                    }
                    startButton.setEnabled(true);
                    stopButton.setEnabled(false);
                }
            }).start();
        });

        stopButton.addActionListener(e -> {
            capturing = false;
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
        });

        return appPanel;

    }

    private static JPanel createLoginPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(new Color(41, 50, 65));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel iconLabel = new JLabel();
        iconLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JLabel userLabel = new JLabel("USERNAME:");
        userLabel.setForeground(Color.WHITE);
        JTextField userField = new JTextField(15);
        userField.setPreferredSize(new Dimension(200, 30));
        JLabel passLabel = new JLabel("PASSWORD:");
        passLabel.setForeground(Color.WHITE);
        JPasswordField passField = new JPasswordField(15);
        passField.setPreferredSize(new Dimension(200, 30));

        JButton loginButton = new JButton("SIGN IN");
        loginButton.setBackground(new Color(51, 153, 255));
        loginButton.setForeground(Color.WHITE);
        loginButton.setPreferredSize(new Dimension(200, 40));
        loginButton.setFocusPainted(false);

        JButton registerButton = new JButton("SIGN UP");
        registerButton.setBackground(new Color(51, 153, 255));
        registerButton.setForeground(Color.WHITE);
        registerButton.setPreferredSize(new Dimension(200, 40));
        registerButton.setFocusPainted(false);

        loginButton.addActionListener(e -> {
            String username = userField.getText();
            String password = new String(passField.getPassword());
            if (authenticate(username, password)) {
                cardLayout.show(mainPanel, "App");
            } else {
                JOptionPane.showMessageDialog(mainFrame, "Invalid username or password", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        registerButton.addActionListener(e -> {
            cardLayout.show(mainPanel, "Register");
        });

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(iconLabel, gbc);

        gbc.gridy = 1;
        panel.add(userLabel, gbc);

        gbc.gridy = 2;
        panel.add(userField, gbc);

        gbc.gridy = 3;
        panel.add(passLabel, gbc);

        gbc.gridy = 4;
        panel.add(passField, gbc);

        gbc.gridy = 5;
        panel.add(loginButton, gbc);

        gbc.gridy = 6;
        panel.add(registerButton, gbc);

        return panel;
    }

    private static boolean authenticate(String username, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?")) {
            stmt.setString(1, username);
            stmt.setString(2, hashPassword(password));
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            logger.error("Error authenticating user", e);
        }
        return false;
    }

    private static boolean registerUser(String username, String password) {
        if (userExists(username)) {
            return false;
        }
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement("INSERT INTO users (username, password) VALUES (?, ?)")) {
            stmt.setString(1, username);
            stmt.setString(2, hashPassword(password));
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            logger.error("Error registering user", e);
        }
        return false;
    }

    private static Icon resizeIcon(ImageIcon icon, int width, int height) {
        Image img = icon.getImage();
        Image resizedImg = img.getScaledInstance(width, height, Image.SCALE_SMOOTH);
        return new ImageIcon(resizedImg);
    }

    private static boolean userExists(String username) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?")) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            logger.error("Error checking if user exists", e);
        }
        return false;
    }
}
