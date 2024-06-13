package IDS;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

//класс для определения потоков
public class FlowProcessor {

    public static void appendUniqueEntry(int time, String srcIp, String dstIp, String protocol) {
        String filePath = "C:\\Users\\Asus\\IdeaProjects\\IDS_1\\src\\main\\java\\IDS\\flows.txt";

        try {
            // Открываем файл для чтения
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            Set<String> uniqueEntries = new HashSet<>();

            // Считываем файл построчно и заполняем множество уникальными комбинациями
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                String uniqueEntry = parts[2] + "," + parts[3] + "," + parts[4];
                uniqueEntries.add(uniqueEntry);
            }
            reader.close();

            // Формируем уникальную строку для новой записи
            String newUniqueEntry = srcIp + "," + dstIp + "," + protocol;

            // Проверяем, есть ли новая строка данных в уникальных комбинациях
            if (!uniqueEntries.contains(newUniqueEntry)) {
                BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true));

                // Находим номер i для новой записи
                int i = uniqueEntries.size() + 1;

                // Создаем строку данных
                String newData = i + "," + time + "," + srcIp + "," + dstIp + "," + protocol;

                // Добавляем новую строку в файл
                writer.write(newData);
                writer.newLine();
                writer.close();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static int getFlowDuration(int time, String srcIp, String dstIp, String protocol) {
        String filePath = "C:\\Users\\Asus\\IdeaProjects\\IDS_1\\src\\main\\java\\IDS\\flows.txt";
        int flowDuration=1; // Инициализируем переменную flowDuration значением 1

        try {
            // Открываем файл для чтения
            BufferedReader reader = new BufferedReader(new FileReader(filePath));

            // Считываем файл построчно
            String line;
            while ((line = reader.readLine()) != null) {
                // Разбиваем строку на отдельные элементы
                String[] parts = line.split(",");

                // Получаем src ip, dst ip и protocol
                String fileSrcIp = parts[2];
                String fileDstIp = parts[3];
                String fileProtocol = parts[4];
                int fileTime = Integer.parseInt(parts[1]);

                // Проверяем, если строка совпадает с текущими параметрами
                if (srcIp.equals(fileSrcIp) && dstIp.equals(fileDstIp) && protocol.equals(fileProtocol) && time!=fileTime) {
                    flowDuration = time - fileTime; // Вычисляем продолжительность потока
                    break; // Прерываем цикл, если найдено совпадение
                }
            }

            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return flowDuration;
    }
}

