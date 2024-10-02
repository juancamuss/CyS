import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

//HAY QUE MIRAR PQ NO PERMITE CIFRAR DOS VECES EL MISMO ARCHIVO EL ZIPS DIFERENTES
public class prueba2 extends JFrame {
    private JTextArea logArea;
    private JButton encryptButton;
    private JButton selectFilesButton;
    private JTextField zipFileNameField;
    private SecretKey aesKey;
    private List<File> selectedFiles;
    private DefaultListModel<String> listModel;
    private JPanel fileListPanel;
    private JScrollPane listScrollPane;

    public prueba2() {
        setTitle("Cifrado y Descifrado de Archivos");
        setSize(600, 500);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        logArea = new JTextArea(10, 40);
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);

        zipFileNameField = new JTextField(20);
        JLabel zipFileNameLabel = new JLabel("Nombre del archivo comprimido:");

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
                    File encryptedFile = AESFileEncryption.encryptFile(zipFile.getAbsolutePath(), aesKey);

                    logArea.append("Archivo comprimido y cifrado: " + encryptedFile.getAbsolutePath() + "\n");

                    // Eliminar archivo ZIP temporal
                    zipFile.delete();

                    // Ocultar la lista de archivos seleccionados
                    fileListPanel.removeAll();
                    fileListPanel.revalidate();
                    fileListPanel.repaint();
                } catch (Exception ex) {
                    logArea.append("Error al comprimir y cifrar los archivos: " + ex.getMessage() + "\n");
                }
            }
        });

        selectedFiles = new ArrayList<>();
        listModel = new DefaultListModel<>();
        fileListPanel = new JPanel();
        fileListPanel.setLayout(new BoxLayout(fileListPanel, BoxLayout.Y_AXIS));
        listScrollPane = new JScrollPane(fileListPanel);
        listScrollPane.setPreferredSize(new Dimension(550, 150));

        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(zipFileNameLabel, gbc);
        gbc.gridx = 1;
        panel.add(zipFileNameField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(selectFilesButton, gbc);
        gbc.gridx = 1;
        panel.add(encryptButton, gbc);
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        panel.add(listScrollPane, gbc);
        gbc.gridy = 3;
        panel.add(scrollPane, gbc);

        add(panel);
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

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new prueba2().setVisible(true);
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
                    ZipEntry zipEntry = new ZipEntry(file.getName());
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
        return encryptedFile;
    }
}