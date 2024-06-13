package IDS;

import org.pcap4j.core.*;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.*;

import weka.core.*;
import weka.classifiers.Classifier;
import weka.core.converters.ArffLoader;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.text.SimpleDateFormat;

import static IDS.FlowProcessor.appendUniqueEntry;
import static IDS.FlowProcessor.getFlowDuration;
import static IDS.GUI.setupGUI;

import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketSniffer {
    static volatile boolean capturing = false;
    static JFrame mainFrame;
    static CardLayout cardLayout;
    static JPanel mainPanel;
    static JTextArea textArea;
    static PcapHandle handle;

    private static Date previousTimestamp = new Date();
    private static long previousArrivalTime = -1;

    private static final short ETHERTYPE_IP = 0x0800;
    private static final int SIZE_ETHERNET = 14;
    private static final int SIZE_TCP = 20;
    private static final SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    private static Classifier classifier;
    private static Instances dataStructure;

    static final Logger logger = LoggerFactory.getLogger(PacketSniffer.class);

    static final String DB_URL = "jdbc:mysql://localhost:3306/ids_database";
    static final String DB_USER = "root";
    static final String DB_PASSWORD = "letmein";

    private static long totalBwdPackets = 0;
    private static long totalFwdPackets = 0;
    private static int ack_count=0;
    private static int syn_count=0;
    private static int fin_count=0;
    private static int urg_count=0;
    private static int rst_count=0;

    public static void main(String[] args) {
        previousTimestamp = new Date();

        setupGUI();

    }

    private static Map<String, Long[]> flowTimestamps = new HashMap<>();

    static void processPacket(Packet packet) throws Exception {

        Date timestamp = new Date();

        byte[] rawData = packet.getRawData();
        if (rawData.length < SIZE_ETHERNET) {
            return;
        }

        byte[] srcMacBytes = new byte[6];
        System.arraycopy(rawData, 6, srcMacBytes, 0, 6);

        // Преобразовать массив байт в строку MAC-адреса
        StringBuilder srcMacAddress = new StringBuilder();
        for (int i = 0; i < srcMacBytes.length; i++) {
            srcMacAddress.append(String.format("%02X", srcMacBytes[i]));
            if (i < srcMacBytes.length - 1) {
                srcMacAddress.append(":");
            }
        }

        // Вывести исходный MAC-адрес
        //System.out.println("Source MAC Address: " + srcMacAddress.toString());

        if(srcMacAddress.toString().equals("E8:9C:25:7F:B4:71")){
            totalFwdPackets++;
        }
        else totalBwdPackets++;

        // Parse Ethernet header
        short etherType = (short) ((rawData[12] << 8) | rawData[13]);


        if (etherType == ETHERTYPE_IP) {
            // Parse IP header
            byte ipHeaderLength = (byte) ((rawData[14] & 0x0F) * 4); // IP header length in bytes

            if (rawData.length < SIZE_ETHERNET + ipHeaderLength) {
                return;
            }
            byte protocol = rawData[SIZE_ETHERNET + 9]; // Protocol field position in IP header

            // Print payload if it's TCP or UDP
            if (protocol == 6 || protocol == 17) { // TCP or UDP
                int finflag = 0;
                int synflag = 0;
                int rstflag = 0;
                int pshflag = 0;
                int ackflag = 0;
                int eceflag = 0;
                int cwrflag = 0;
                if (protocol == 6) {
                    byte[] RawData = packet.getRawData();
                    if (RawData.length < 34) {
                        // Проверка длины данных, чтобы убедиться, что есть достаточно байт для чтения флагов TCP
                        System.out.println("Недостаточно данных для чтения флагов TCP.");
                        return;
                    }

                    int flagsByteIndex = 13 + 20; // Индекс байта флагов TCP
                    byte flagsByte = RawData[flagsByteIndex];

                    finflag = 0;
                    synflag = 0;
                    rstflag = 0;
                    int urgflag = 0;
                    pshflag = 0;
                    ackflag = 0;
                    eceflag = 0;
                    cwrflag = 0;

                    boolean finFlag = (flagsByte & 0x01) != 0; // 0x01 - бит флага FIN
                    boolean synFlag = (flagsByte & 0x02) != 0; // 0x02 - бит флага SYN
                    boolean rstFlag = (flagsByte & 0x04) != 0; // 0x04 - бит флага RST
                    boolean urgFlag = (flagsByte & 0x20) != 0; // 0x20 - бит флага URG
                    boolean pshFlag = (flagsByte & 0x08) != 0; // 0x08 - бит флага PSH
                    boolean ackFlag = (flagsByte & 0x10) != 0; // 0x10 - бит флага ACK
                    boolean eceFlag = (flagsByte & 0x40) != 0; // 0x40 - бит флага ECE
                    boolean cwrFlag = (flagsByte & 0x80) != 0; // 0x80 - бит флага CWR

                    if (cwrFlag) {
                        cwrflag = 1;
                    }
                    if (eceFlag) {
                        eceflag = 1;
                    }
                    if (pshFlag) {
                        pshflag = 1;
                    }
                    if (ackFlag) {
                        ack_count++;
                        ackflag = 1;
                    }
                    if (synFlag) {
                        syn_count++;
                        synflag = 1;
                    }
                    if (finFlag) {
                        fin_count++;
                        finflag = 1;
                    }
                    if (urgFlag) {
                        urg_count++;
                        urgflag = 1;
                    }
                    if (rstFlag) {
                        rst_count++;
                        rstflag = 1;
                    }
                }

                String sourceIP = extractSourceIP(rawData);
                String destinationIP = extractDestinationIP(rawData);

                int time = getSecondsSinceMidnight();

                // Позиция начала TCP или UDP заголовка
                int transportHeaderStart = SIZE_ETHERNET + ipHeaderLength;
                // Номер порта назначения в TCP или UDP заголовке находится смещением 2 байт от начала заголовка
                int destinationPortPosition = transportHeaderStart + 2;
                // Извлекаем значение номера порта назначения из двух байтов
                int destinationPort = ((rawData[destinationPortPosition] & 0xFF) << 8) | (rawData[destinationPortPosition + 1] & 0xFF);
                int sourcePort = ((rawData[transportHeaderStart] & 0xFF) << 8) | (rawData[transportHeaderStart + 1] & 0xFF);

//                System.out.println("BWD " + totalBwdPackets);
//                System.out.println("FWD " + totalFwdPackets);

                int HTTP = 0;
                int HTTPS = 0;
                int DNS = 0;
                int TELNET = 0;
                int SMTP = 0;
                int SSH = 0;
                int IRC = 0;
                int TCP = 0;
                int UDP = 0;
                int DHCP = 0;
                int ARP = 0;
                int ICMP = 0;

                if (destinationPort == 80) {
                    HTTP = 1;
                }
                if (destinationPort == 443) {
                    HTTPS = 1;
                }
                if (destinationPort == 53) {
                    DNS = 1;
                }
                if (destinationPort == 23) {
                    TELNET = 1;
                }
                if (destinationPort == 80) {
                    HTTP = 1;
                }
                if (destinationPort == 25) {
                    SMTP = 1;
                }
                if (destinationPort == 22) {
                    SSH = 1;
                }
                if (destinationPort == 6667) {
                    IRC = 1;
                }
                if (protocol == 6) {
                    TCP = 1;
                }
                if (protocol == 17) {
                    UDP = 1;
                }
                if (destinationPort == 67 || destinationPort == 68) {
                    DHCP = 1;
                }
                if (etherType == 0x0806) {
                    ARP = 1;
                }
                if (protocol == 1) {
                    ICMP = 1;
                }
                int totalPacketSize = rawData.length;

                timestamp = new Date();
                int IAT = (int) (timestamp.getTime() - previousTimestamp.getTime());


                // Шаг 1: Загрузка модели
                loadModel();
                // Шаг 2: Инициализация структуры данных
                initializeDataStructure();
                // Шаг 3: Добавление данных и предикт
                appendUniqueEntry(time,sourceIP,destinationIP, String.valueOf(protocol));
                recordAndPredict(getFlowDuration(time,sourceIP,destinationIP, String.valueOf(protocol)), ipHeaderLength, protocol, finflag, synflag, rstflag, pshflag, ackflag, eceflag, cwrflag, ack_count,
                        syn_count, fin_count, urg_count, rst_count, HTTP, HTTPS, DNS, TELNET, SMTP, SSH, IRC, TCP, UDP, DHCP, ARP, ICMP,
                        totalPacketSize, IAT, sourceIP, destinationIP);



                previousTimestamp = timestamp;


                int payloadOffset = SIZE_ETHERNET + ipHeaderLength;
                int payloadLength = rawData.length - payloadOffset;
                if (payloadLength > 0) {
                    byte[] payload = Arrays.copyOfRange(rawData, payloadOffset, rawData.length);
                } else {
                    System.out.println("No payload.");
                    printToTextArea("No payload.");
                }
            }
        }
    }


    private static void initializeDataStructure() throws Exception {
        File arffFile = new File("C:\\Users\\Asus\\IdeaProjects\\IDS_1\\src\\main\\java\\IDS\\predictions.arff");

        BufferedReader reader = new BufferedReader(new FileReader(arffFile));
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        int lineNumber = 0;

        while ((line = reader.readLine()) != null) {
            lineNumber++;
            // Добавляем строки до 11 строки в StringBuilder
            if (lineNumber < 38) {
                stringBuilder.append(line).append(System.lineSeparator());
            }
        }

        // Закрываем BufferedReader
        reader.close();

        // Перезаписываем файл ARFF с удалением содержимого после 11 строки
        BufferedWriter writer = new BufferedWriter(new FileWriter(arffFile));
        writer.write(stringBuilder.toString());
        writer.close();

        ArffLoader loader = new ArffLoader();
        loader.setFile(arffFile);
        dataStructure = loader.getDataSet();
        if (dataStructure.classIndex() == -1) {
            dataStructure.setClassIndex(dataStructure.numAttributes() - 1);
        }
    }

    private static void loadModel() throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("C:\\Users\\Asus\\IdeaProjects\\IDS_1\\src\\main\\java\\IDS\\models\\smo.model"));
        classifier = (Classifier) ois.readObject();
        ois.close();
    }

    private static void appendToARFF(String line) throws IOException {
        FileWriter fw = new FileWriter("C:\\Users\\Asus\\IdeaProjects\\IDS_1\\src\\main\\java\\IDS\\predictions.arff", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(line);
        bw.newLine();
        bw.close();
        fw.close();
    }
    private static void recordAndPredict(int flowDuration, int ipHeaderLength, int protocol, int finflag, int synflag, int rstflag, int pshflag, int ackflag, int eceflag, int cwrflag, int A_count,
                                         int S_count, int F_count, int U_count, int R_count, int HTTP, int HTTPS, int DNS, int TELNET, int SMTP, int SSH, int IRC, int TCP, int UDP,
                                         int DHCP, int ARP, int ICMP, int totalPacketSize, int IAT, String sourceIP, String destinationIP) throws Exception {
        // Форматирование строки данных
        String newDataLine = flowDuration + "," + ipHeaderLength + "," + protocol + "," + finflag + "," + synflag + "," + rstflag
                + "," + pshflag + "," + ackflag + "," + eceflag + "," + cwrflag + "," + A_count +  "," + S_count + "," + F_count + "," + U_count
                + "," + R_count + "," + HTTP + "," + HTTPS + "," + DNS + "," + TELNET + "," + SMTP + "," + SSH + "," + IRC + "," + TCP
                + "," + UDP + "," + DHCP + "," + ARP + "," + ICMP + "," + totalPacketSize + "," + IAT + "," + "?";

        // Запись данных в ARFF файл
        appendToARFF(newDataLine);

        //Обновление данных и предсказание для нового экземпляра
        predictForNewData(sourceIP, destinationIP, String.valueOf(protocol));
    }

    private static void predictForNewData(String sourceIP, String destinationIP, String protocol) throws Exception {
        ArffLoader loader = new ArffLoader();
        loader.setSource(new File("C:\\Users\\Asus\\IdeaProjects\\IDS_1\\src\\main\\java\\IDS\\predictions.arff"));
        Instances newData = loader.getDataSet();
        if (newData.classIndex() == -1) {
            newData.setClassIndex(newData.numAttributes() - 1);
        }

        // Получение последнего экземпляра (нового добавленного)
        Instance newInstance = newData.lastInstance();

        // Предсказание класса
        double predictedClass = classifier.classifyInstance(newInstance);
        String predictedClassLabel = newData.classAttribute().value((int) predictedClass);


            printToTextArea("Новый экземпляр: " + newInstance);
            printToTextArea("Предсказанный класс: " + predictedClassLabel);

        // Сохранение в базу данных, если predictedClassLabel != "BenignTraffic"

            Date timestamp = new Date();
            if(!predictedClassLabel.equals("BenignTraffic")) {
                saveToDatabase(predictedClassLabel, formatter.format(timestamp), sourceIP, destinationIP, String.valueOf(protocol));
            }
    }





    static void printToTextArea(String text) {
        SwingUtilities.invokeLater(() -> textArea.append(text + "\n"));
    }

    private static String formatMacAddress(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X", mac[i]));
            if (i < mac.length - 1) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    private static String formatIpAddress(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    private static boolean isIPv4(byte[] data) {
        // Первый байт содержит версию и длину заголовка
        int version = (data[0] >> 4) & 0xF;
        return version == 4;
    }

    private static String extractSourceIP(byte[] data) {
        int srcAddrStart = 12; // Начало IP-адреса источника в заголовке IPv4
        return (data[srcAddrStart] & 0xFF) + "." +
                (data[srcAddrStart + 1] & 0xFF) + "." +
                (data[srcAddrStart + 2] & 0xFF) + "." +
                (data[srcAddrStart + 3] & 0xFF);
    }

    private static String extractDestinationIP(byte[] data) {
        int destAddrStart = 16; // Начало IP-адреса назначения в заголовке IPv4
        return (data[destAddrStart] & 0xFF) + "." +
                (data[destAddrStart + 1] & 0xFF) + "." +
                (data[destAddrStart + 2] & 0xFF) + "." +
                (data[destAddrStart + 3] & 0xFF);
    }

    public static int getSecondsSinceMidnight() {
        // Получаем текущее время в миллисекундах
        long currentTimeMillis = System.currentTimeMillis();

        // Получаем текущее время в объекте Date
        Date currentDate = new Date(currentTimeMillis);

        // Получаем часы, минуты и секунды
        int hours = currentDate.getHours();
        int minutes = currentDate.getMinutes();
        int seconds = currentDate.getSeconds();

        // Вычисляем общее количество секунд с начала дня
        int totalSeconds = hours * 3600 + minutes * 60 + seconds;

        return totalSeconds;
    }

    public static long calculateCurrentIAT(long currentArrivalTime) {
        long iat = 1; // Переменная для хранения IAT, инициализирована значением -1

        if (previousArrivalTime != -1) {
            iat = currentArrivalTime - previousArrivalTime; // Вычисление IAT как разницы между текущим и предыдущим временем прибытия
        }

        previousArrivalTime = currentArrivalTime; // Обновление предыдущего времени прибытия

        return iat; // Возвращение текущего IAT
    }

    private static void saveToDatabase(String predictedClassLabel, String timestamp, String sourceIP, String destinationIP, String protocol) {

        String query = "INSERT INTO predictions (predicted_class_label, timestamp, src_ip, dst_ip, protocol) VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, predictedClassLabel);
            pstmt.setString(2, timestamp);
            pstmt.setString(3, sourceIP);
            pstmt.setString(4, destinationIP);
            pstmt.setString(5, protocol);

            pstmt.executeUpdate();
//            System.out.println("Data has been inserted successfully.");

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
}

