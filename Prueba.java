import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class prueba2 {
    private JFrame listFrame;
    private JFrame encryptFrame;
    private JTextArea logArea;
    private JButton encryptButton;
    private JButton selectFilesButton;
    private JTextField zipFileNameField;
    private SecretKey aesKey;
    private List<File> selectedFiles;
    private DefaultListModel<String> listModel;
    private JPanel fileListPanel;
    private JScrollPane listScrollPane;
    private JList<String> encFileList;

    public prueba2() {
        // Crear la ventana de lista de archivos
        listFrame = new JFrame("Lista de Archivos Cifrados");
        listFrame.setSize(600, 500);
        listFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        listFrame.setLocationRelativeTo(null);

        JPanel listPanel = new JPanel(new BorderLayout());
        encFileList = new JList<>(getEncFiles());
        JScrollPane encFileScrollPane = new JScrollPane(encFileList);
        JButton goToEncryptButton = new JButton("Ir a Comprimir y Cifrar");
        goToEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                listFrame.setVisible(false);
                encryptFrame.setVisible(true);
            }
        });
        listPanel.add(encFileScrollPane, BorderLayout.CENTER);
        listPanel.add(goToEncryptButton, BorderLayout.NORTH);
        listFrame.add(listPanel);

        // Crear la ventana de compresión y cifrado
        encryptFrame = new JFrame("Comprimir y Cifrar Archivos");
        encryptFrame.setSize(600, 500);
        encryptFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        encryptFrame.setLocationRelativeTo(null);

        JPanel encryptPanel = new JPanel();
        encryptPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;

        zipFileNameField = new JTextField(20);
        JLabel zipFileNameLabel = new JLabel("Nombre del archivo comprimido:");
        encryptPanel.add(zipFileNameLabel, gbc);
        gbc.gridx = 1;
        encryptPanel.add(zipFileNameField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;

        selectFilesButton = new JButton("Seleccionar Archivos");
        selectFilesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setMultiSelectionEnabled(true);
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Archivos Multimedia", "mp4", "mp3", "jpg", "png");
                fileChooser.setFileFilter(filter);

                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File[] files = fileChooser.getSelectedFiles();
                    for (File file : files) {
                        selectedFiles.add(file);
                        listModel.addElement(file.getName());
                        addFileToPanel(file);
                    }
                }
            }
        });
        encryptPanel.add(selectFilesButton, gbc);
        gbc.gridx = 1;
        gbc.gridy = 1;

        encryptButton = new JButton("Cifrar Archivos");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String zipFileName = zipFileNameField.getText();
                if (zipFileName.isEmpty()) {
                    logArea.append("Por favor, introduce un nombre para el archivo comprimido.\n");
                    return;
                }

                if (selectedFiles.isEmpty()) {
                    logArea.append("Por favor, selecciona al menos un archivo para comprimir y cifrar.\n");
                    return;
                }

                try {
                    // Crear archivo ZIP
                    File zipFile = new File(zipFileName + ".zip");
                    List<String> filePaths = new ArrayList<>();
                    for (File file : selectedFiles) {
                        filePaths.add(file.getAbsolutePath());
                    }
                    compressFilesToZip(filePaths, zipFile.getAbsolutePath());

                    // Cifrar archivo ZIP
                    aesKey = AESFileEncryption.generateAESKey();
                    AESFileEncryption.saveAESKey(aesKey, "aesKey.key"); // Guardar la clave AES en un archivo
                    System.out.println("Clave AES guardada: " + Base64.getEncoder().encodeToString(aesKey.getEncoded())); // Comprobar si la clave se guarda

                    // Cargar la clave AES desde el archivo
                    SecretKey loadedKey = AESFileEncryption.loadAESKey("aesKey.key");
                    System.out.println("Clave AES cargada: " + Base64.getEncoder().encodeToString(loadedKey.getEncoded())); // Comprobar si la clave se carga

                    // Verificar que la clave guardada y la cargada son iguales
                    if (Base64.getEncoder().encodeToString(aesKey.getEncoded()).equals(Base64.getEncoder().encodeToString(loadedKey.getEncoded()))) {
                        System.out.println("La clave AES se ha guardado y cargado correctamente.");
                    } else {
                        System.out.println("Error: La clave AES guardada y cargada no coinciden.");
                    }

                    File encryptedFile = AESFileEncryption.encryptFile(zipFile.getAbsolutePath(), aesKey);

                    logArea.append("Archivo comprimido y cifrado: " + encryptedFile.getAbsolutePath() + "\n");

                    // Eliminar archivo ZIP temporal
                    zipFile.delete();

                    // Ocultar la lista de archivos seleccionados
                    fileListPanel.removeAll();
                    fileListPanel.revalidate();
                    fileListPanel.repaint();

                    // Refrescar la lista de archivos .enc
                    refreshEncFileList();
                } catch (Exception ex) {
                    logArea.append("Error al comprimir y cifrar los archivos: " + ex.getMessage() + "\n");
                }
            }
        });
        encryptPanel.add(encryptButton, gbc);
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;

        JButton backButton = new JButton("Volver a la Lista de Archivos");
        backButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                encryptFrame.setVisible(false);
                listFrame.setVisible(true);
            }
        });
        encryptPanel.add(backButton, gbc);

        logArea = new JTextArea(10, 40);
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        gbc.gridy = 3;
        encryptPanel.add(scrollPane, gbc);

        selectedFiles = new ArrayList<>();
        listModel = new DefaultListModel<>();
        fileListPanel = new JPanel();
        fileListPanel.setLayout(new BoxLayout(fileListPanel, BoxLayout.Y_AXIS));
        listScrollPane = new JScrollPane(fileListPanel);
        listScrollPane.setPreferredSize(new Dimension(550, 150));
        gbc.gridy = 4;
        encryptPanel.add(listScrollPane, gbc);

        encryptFrame.add(encryptPanel);
    }

    private void addFileToPanel(File file) {
        JPanel filePanel = new JPanel(new BorderLayout());
        filePanel.setPreferredSize(new Dimension(500, 30));
        JLabel fileNameLabel = new JLabel(file.getName());
        JButton removeButton = new JButton("Eliminar");
        removeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectedFiles.remove(file);
                listModel.removeElement(file.getName());
                fileListPanel.remove(filePanel);
                fileListPanel.revalidate();
                fileListPanel.repaint();
            }
        });
        filePanel.add(fileNameLabel, BorderLayout.CENTER);
        filePanel.add(removeButton, BorderLayout.EAST);
        fileListPanel.add(filePanel);
        fileListPanel.revalidate();
        fileListPanel.repaint();
    }

    private DefaultListModel<String> getEncFiles() {
        DefaultListModel<String> model = new DefaultListModel<>();
        File dir = new File(System.getProperty("user.dir"));
        File[] files = dir.listFiles((d, name) -> name.endsWith(".enc"));
        if (files != null) {
            for (File file : files) {
                model.addElement(file.getName());
            }
        }
        return model;
    }

    private void refreshEncFileList() {
        DefaultListModel<String> model = getEncFiles();
        encFileList.setModel(model);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                prueba2 app = new prueba2();
                app.listFrame.setVisible(true);
            }
        });
    }

    // Método para comprimir de 1 a N archivos en un archivo ZIP
    public static File compressFilesToZip(List<String> filePaths, String zipFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(zipFilePath);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            for (String filePath : filePaths) {
                File file = new File(filePath);
                try (FileInputStream fis = new FileInputStream(file)) {
                    // Generar un nombre único para cada entrada en el ZIP
                    String timestamp = new SimpleDateFormat("yyyyMMddHHmmssSSS").format(new Date());
                    String zipEntryName = file.getName() + "_" + timestamp;
                    ZipEntry zipEntry = new ZipEntry(zipEntryName);
                    zos.putNextEntry(zipEntry);

                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        zos.write(buffer, 0, bytesRead);
                    }
                    zos.closeEntry();
                }
            }
        }
        return new File(zipFilePath);
    }
}

class AESFileEncryption {
    // Método para generar una clave AES de 128 bits
    public static SecretKey generateAESKey() throws Exception {
        // Crear un generador de claves para el algoritmo AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        // Inicializar el generador para producir claves de 128 bits
        keyGen.init(128); // AES con 128 bits
        // Generar y retornar la clave
        return keyGen.generateKey();
    }

    // Método para guardar la clave AES en un archivo
    public static void saveAESKey(SecretKey key, String fileName) throws IOException {
        byte[] encodedKey = key.getEncoded();
        String encodedKeyString = Base64.getEncoder().encodeToString(encodedKey);
        try (FileWriter fw = new FileWriter(fileName)) {
            fw.write(encodedKeyString);
        }
    }

    // Método para leer la clave AES desde un archivo
    public static SecretKey loadAESKey(String fileName) throws IOException {
        byte[] encodedKey;
        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            String encodedKeyString = br.readLine();
            encodedKey = Base64.getDecoder().decode(encodedKeyString);
        }
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        System.out.println("Clave AES cargada: " + Base64.getEncoder().encodeToString(key.getEncoded())); // Comprobar si la clave se carga
        return key;
    }

    // Método para cifrar un archivo utilizando una clave AES
    public static File encryptFile(String filePath, SecretKey key) throws Exception {
        // Crear un objeto Cipher con el modo AES/CBC/PKCS5Padding (AES en modo CBC con padding PKCS5)
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // Crear un generador de números aleatorios para generar el IV (Vector de Inicialización)
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16]; // AES usa un IV de 16 bytes (128 bits)
        random.nextBytes(iv); // Llenar el IV con bytes aleatorios
        IvParameterSpec ivSpec = new IvParameterSpec(iv); // Especificar el IV
        // Inicializar el Cipher en modo cifrado con la clave y el IV
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        // Referencias a los archivos de entrada (archivo original) y salida (archivo cifrado)
        File inputFile = new File(filePath);
        File encryptedFile = new File(filePath + ".enc"); // El archivo cifrado tendrá extensión ".enc"

        // Leer el archivo de entrada y escribir el archivo cifrado
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(encryptedFile)) {
            // Escribir el IV al inicio del archivo cifrado, para usarlo luego en el descifrado
            fos.write(iv);
            byte[] buffer = new byte[1024]; // Buffer para leer el archivo en bloques de 1024 bytes
            int bytesRead;
            // Leer el archivo de entrada y cifrarlo por bloques
            while ((bytesRead = fis.read(buffer)) != -1) {
                // Cifrar el bloque leído
                byte[] output = cipher.update(buffer, 0, bytesRead);
                // Si el cifrado produjo salida (output), escribirla en el archivo cifrado
                if (output != null) fos.write(output);
            }
            // Finalizar el cifrado y procesar cualquier bloque restante
            byte[] output = cipher.doFinal();
            // Escribir cualquier dato resultante del método doFinal()
            if (output != null) fos.write(output);
        }
        System.out.println("Archivo cifrado: " + encryptedFile.getAbsolutePath());
        return encryptedFile;
    }

    // Método para descifrar un archivo cifrado utilizando una clave AES
    public static void decryptFile(String encryptedFilePath, SecretKey key) throws Exception {
        // Crear un objeto Cipher con el mismo modo que en el cifrado (AES/CBC/PKCS5Padding)
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Referencias al archivo cifrado (entrada) y al archivo descifrado (salida)
        File encryptedFile = new File(encryptedFilePath);
        File decryptedFile = new File(encryptedFilePath.replace(".enc", "_decrypted")); // Nombre del archivo descifrado

        // Leer el archivo cifrado y escribir el archivo descifrado
        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(decryptedFile)) {

            // Leer el IV que se guardó al inicio del archivo cifrado
            byte[] iv = new byte[16];
            fis.read(iv); // Leer los primeros 16 bytes, que corresponden al IV
            IvParameterSpec ivSpec = new IvParameterSpec(iv); // Especificar el IV leído

            // Inicializar el Cipher en modo descifrado con la clave y el IV
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            // Leer el archivo cifrado y descifrarlo por bloques
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                // Descifrar el bloque leído
                byte[] output = cipher.update(buffer, 0, bytesRead);
                // Si el descifrado produjo salida (output), escribirla en el archivo descifrado
                if (output != null) fos.write(output);
            }
            // Finalizar el descifrado y procesar cualquier bloque restante
            byte[] output = cipher.doFinal();
            // Escribir cualquier dato resultante del método doFinal()
            if (output != null) fos.write(output);
        }
    }
}