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

public class FileEncryptionGUI extends JFrame {
    // Área de texto para mostrar los logs
    private JTextArea logArea;
    // Botón para cifrar archivo
    private JButton encryptButton;
    // Botón para descifrar archivo
    private JButton decryptButton;
    // Clave AES que se genera al cifrar el archivo (se guarda temporalmente en la memoria)
    private SecretKey aesKey;  
    // Archivo seleccionado por el usuario para cifrar/descifrar
    private File selectedFile;

    // Constructor de la interfaz gráfica
    public FileEncryptionGUI() {
        // Configuración de la ventana principal (título, tamaño, comportamiento de cierre)
        setTitle("Cifrado y Descifrado de Archivos");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Centrar la ventana en la pantalla

        // Configuración del área de texto para mostrar los logs
        logArea = new JTextArea(10, 30);
        logArea.setEditable(false); // No se permite la edición directa del texto
        JScrollPane scrollPane = new JScrollPane(logArea); // Se añade una barra de desplazamiento

        // Botón para seleccionar y cifrar un archivo
        encryptButton = new JButton("Cifrar Archivo");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Selector de archivos para elegir el archivo a cifrar
                JFileChooser fileChooser = new JFileChooser();
                // Filtro para mostrar solo ciertos tipos de archivos (multimedia)
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Archivos Multimedia", "mp4", "mp3", "jpg", "png");
                fileChooser.setFileFilter(filter);

                // Abrir el diálogo de selección de archivo y verificar si el usuario selecciona un archivo
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile(); // Obtener el archivo seleccionado
                    logArea.append("Archivo seleccionado: " + selectedFile.getAbsolutePath() + "\n");

                    // Cifrar el archivo utilizando AES
                    try {
                        aesKey = AESFileEncryption.generateAESKey(); // Generar la clave AES
                        AESFileEncryption.encryptFile(selectedFile.getAbsolutePath(), aesKey); // Cifrar el archivo
                        logArea.append("Archivo cifrado correctamente.\n");
                    } catch (Exception ex) {
                        logArea.append("Error al cifrar el archivo: " + ex.getMessage() + "\n");
                    }
                }
            }
        });

        // Botón para descifrar el archivo seleccionado
        decryptButton = new JButton("Descifrar Archivo");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Verificar que el archivo esté seleccionado y que la clave AES esté disponible
                if (selectedFile != null && aesKey != null) {
                    logArea.append("Descifrando el archivo...\n");

                    // Crear la ruta del archivo cifrado (añadiendo ".enc" al nombre del archivo original)
                    String encryptedFilePath = selectedFile.getAbsolutePath() + ".enc";
                    File encryptedFile = new File(encryptedFilePath);

                    // Verificar si el archivo cifrado existe
                    if (encryptedFile.exists()) {
                        try {
                            // Descifrar el archivo
                            AESFileEncryption.decryptFile(encryptedFilePath, aesKey);
                            logArea.append("Archivo descifrado correctamente.\n");
                        } catch (Exception ex) {
                            logArea.append("Error al descifrar el archivo: " + ex.getMessage() + "\n");
                        }
                    } else {
                        logArea.append("No se encontró el archivo cifrado: " + encryptedFilePath + "\n");
                    }
                } else {
                    logArea.append("Primero selecciona un archivo y cárgalo.\n");
                }
            }
        });

        // Panel para contener los botones de cifrado y descifrado
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(encryptButton); // Añadir botón de cifrar
        buttonPanel.add(decryptButton); // Añadir botón de descifrar

        // Layout principal de la ventana: logArea en el centro y botones en la parte inferior
        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.CENTER); // Añadir el área de logs al centro de la ventana
        add(buttonPanel, BorderLayout.SOUTH); // Añadir el panel de botones en la parte inferior
    }

    // Método principal para ejecutar la aplicación
    public static void main(String[] args) {
        // Ejecutar la interfaz gráfica en el hilo de eventos de Swing
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // Crear instancia de la interfaz gráfica y hacerla visible
                FileEncryptionGUI gui = new FileEncryptionGUI();
                gui.setVisible(true);
            }
        });
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
    public static void encryptFile(String filePath, SecretKey key) throws Exception {
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

     public static File compressFilesToZip(List<String> filePaths, String zipFilePath) throws IOException {
        // Crear un objeto FileOutputStream para el archivo ZIP de salida
        try (FileOutputStream fos = new FileOutputStream(zipFilePath);
             // Crear un objeto ZipOutputStream a partir del FileOutputStream
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            // Iterar sobre la lista de archivos
            for (String filePath : filePaths) {
                File file = new File(filePath);
                // Crear un objeto FileInputStream para el archivo actual
                try (FileInputStream fis = new FileInputStream(file)) {
                    // Crear un objeto ZipEntry con el nombre del archivo y añadirlo al ZipOutputStream
                    ZipEntry zipEntry = new ZipEntry(file.getName());
                    zos.putNextEntry(zipEntry);

                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    // Leer el contenido del archivo y escribirlo en el ZipOutputStream
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        zos.write(buffer, 0, bytesRead);
                    }
                    // Cerrar la entrada del archivo en el ZipOutputStream
                    zos.closeEntry();
                }
            }
        }
        // Retornar el archivo ZIP comprimido
        return new File(zipFilePath);
    }
}
}

/*
public class FileEncryptionGUI extends JFrame {
    private JTextArea logArea;
    private JButton encryptButton;
    private JButton decryptButton;
    private SecretKey aesKey;  // La clave AES que será generada al cifrar el archivo
    private File selectedFile;

    public FileEncryptionGUI() {
        // Configuración de la ventana principal
        setTitle("Cifrado y Descifrado de Archivos");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // Área de texto para mostrar información de logs
        logArea = new JTextArea(10, 30);
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);

        // Botón para seleccionar y cifrar un archivo
        encryptButton = new JButton("Cifrar Archivo");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Archivos Multimedia", "mp4", "mp3", "jpg", "png");
                fileChooser.setFileFilter(filter);

                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                    logArea.append("Archivo seleccionado: " + selectedFile.getAbsolutePath() + "\n");

                    // Cifrar el archivo usando AES
                    try {
                        aesKey = AESFileEncryption.generateAESKey();
                        AESFileEncryption.encryptFile(selectedFile.getAbsolutePath(), aesKey);
                        logArea.append("Archivo cifrado correctamente.\n");
                    } catch (Exception ex) {
                        logArea.append("Error al cifrar el archivo: " + ex.getMessage() + "\n");
                    }
                }
            }
        });

        // Botón para descifrar el archivo seleccionado
        decryptButton = new JButton("Descifrar Archivo");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedFile != null && aesKey != null) {
                    logArea.append("Descifrando el archivo...\n");

                    // Añadir la extensión ".enc" al archivo cifrado
                    String encryptedFilePath = selectedFile.getAbsolutePath() + ".enc";
                    File encryptedFile = new File(encryptedFilePath);

                    if (encryptedFile.exists()) {
                        try {
                            // Llamar a la función para descifrar el archivo
                            AESFileEncryption.decryptFile(encryptedFilePath, aesKey);
                            logArea.append("Archivo descifrado correctamente.\n");
                        } catch (Exception ex) {
                            logArea.append("Error al descifrar el archivo: " + ex.getMessage() + "\n");
                        }
                    } else {
                        logArea.append("No se encontró el archivo cifrado: " + encryptedFilePath + "\n");
                    }
                } else {
                    logArea.append("Primero selecciona un archivo y cárgalo.\n");
                }
            }
        });

        // Panel para botones
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        // Layout de la ventana
        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                FileEncryptionGUI gui = new FileEncryptionGUI();
                gui.setVisible(true);
            }
        });
    }
}


class AESFileEncryption {
    // Método para generar la clave AES
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES 128 bits
        return keyGen.generateKey();
    }

    // Método para cifrar el archivo
    public static void encryptFile(String filePath, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        File inputFile = new File(filePath);
        File encryptedFile = new File(filePath + ".enc");

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(encryptedFile)) {
            fos.write(iv); // Guardar IV al inicio
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) fos.write(output);
            }
            byte[] output = cipher.doFinal();
            if (output != null) fos.write(output);
        }
    }

    // Método para descifrar el archivo
    public static void decryptFile(String encryptedFilePath, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Leer el archivo cifrado
        File encryptedFile = new File(encryptedFilePath);
        File decryptedFile = new File(encryptedFilePath.replace(".enc", "_decrypted"));

        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(decryptedFile)) {

            // Leer el IV que está almacenado al principio del archivo
            byte[] iv = new byte[16];
            fis.read(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Inicializar el cifrador en modo DESCIFRADO
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            // Leer el archivo cifrado y descifrarlo
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) fos.write(output);
            }
            byte[] output = cipher.doFinal();
            if (output != null) fos.write(output);
        }
    }
}*/
