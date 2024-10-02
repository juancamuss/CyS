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
import java.security.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class FileEncryptionGUI extends JFrame {
    private JTextArea logArea;
    private JButton selectFilesButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private SecretKey aesKey;
    private File[] selectedFiles;
    private KeyPair rsaKeyPair;

    public FileEncryptionGUI() {
        setTitle("Cifrado y Descifrado de Archivos");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        logArea = new JTextArea(10, 40);
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);

        // Botón para seleccionar archivos
        selectFilesButton = new JButton("Seleccionar Archivos");
        selectFilesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setMultiSelectionEnabled(true); // Habilitar selección múltiple
                FileNameExtensionFilter filter = new FileNameExtensionFilter(
                        "Archivos Multimedia", "mp4", "mp3", "jpg", "png");
                fileChooser.setFileFilter(filter);

                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFiles = fileChooser.getSelectedFiles(); // Obtener archivos seleccionados
                    logArea.append("Archivos seleccionados:\n");
                    for (File file : selectedFiles) {
                        logArea.append(file.getAbsolutePath() + "\n");
                    }
                }
            }
        });

        encryptButton = new JButton("Cifrar Archivos");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedFiles != null && selectedFiles.length > 0) {
                    try {
                        aesKey = AESFileEncryption.generateAESKey(); 
                        rsaKeyPair = RSAKeyPairGenerator.generateKeyPair(); 

                        for (File file : selectedFiles) {
                            byte[] encryptedAESKey = RSAEncryption.encryptAESKey(aesKey, rsaKeyPair.getPublic());
                            KeyFileWriter.saveEncryptedAESKey(encryptedAESKey, "aes_key_encrypted.key");

                            AESFileEncryption.encryptFile(file.getAbsolutePath(), aesKey);
                            logArea.append("Archivo cifrado correctamente: " + file.getName() + "\n");
                        }
                        
                        FileCompressor.compressFiles(selectedFiles);
                        logArea.append("Archivos comprimidos correctamente.\n");
                    } catch (Exception ex) {
                        logArea.append("Error al cifrar/comprimir los archivos: " + ex.getMessage() + "\n");
                    }
                } else {
                    logArea.append("Primero selecciona los archivos para cifrar.\n");
                }
            }
        });

        decryptButton = new JButton("Descifrar Archivos");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (selectedFiles != null && aesKey != null) {
                    logArea.append("Descifrando archivos...\n");

                    try {
                        for (File file : selectedFiles) {
                            String encryptedFilePath = file.getAbsolutePath() + ".enc";
                            AESFileEncryption.decryptFile(encryptedFilePath, aesKey);
                            logArea.append("Archivo descifrado correctamente: " + file.getName() + "\n");
                        }
                    } catch (Exception ex) {
                        logArea.append("Error al descifrar los archivos: " + ex.getMessage() + "\n");
                    }
                } else {
                    logArea.append("Primero selecciona los archivos y cárgalos.\n");
                }
            }
        });

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(selectFilesButton); // Botón para seleccionar archivos
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

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

// Clase para manejar la compresión de archivos
class FileCompressor {
    public static void compressFiles(File[] files) throws Exception {
        String zipFileName = files[0].getParent() + "/archivos_comprimidos.zip";
        FileOutputStream fos = new FileOutputStream(zipFileName);
        ZipOutputStream zipOut = new ZipOutputStream(fos);

        for (File file : files) {
            FileInputStream fis = new FileInputStream(file.getAbsolutePath() + ".enc"); // Archivos cifrados
            ZipEntry zipEntry = new ZipEntry(file.getName() + ".enc");
            zipOut.putNextEntry(zipEntry);

            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) >= 0) {
                zipOut.write(buffer, 0, length);
            }
            fis.close();
        }

        zipOut.close();
        fos.close();
    }
}

// Clase para cifrado AES
class AESFileEncryption {
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES-128
        return keyGen.generateKey();
    }

    public static void encryptFile(String filePath, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16])); // IV de 16 bytes (todo ceros)

        FileInputStream fis = new FileInputStream(filePath);
        FileOutputStream fos = new FileOutputStream(filePath + ".enc");

        byte[] buffer = new byte[1024];
        int length;
        while ((length = fis.read(buffer)) != -1) {
            byte[] encrypted = cipher.update(buffer, 0, length);
            if (encrypted != null) {
                fos.write(encrypted);
            }
        }
        byte[] finalBytes = cipher.doFinal();
        if (finalBytes != null) {
            fos.write(finalBytes);
        }
        fis.close();
        fos.close();
    }

    public static void decryptFile(String encryptedFilePath, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(new byte[16]));

        FileInputStream fis = new FileInputStream(encryptedFilePath);
        FileOutputStream fos = new FileOutputStream(encryptedFilePath.replace(".enc", ".dec"));

        byte[] buffer = new byte[1024];
        int length;
        while ((length = fis.read(buffer)) != -1) {
            byte[] decrypted = cipher.update(buffer, 0, length);
            if (decrypted != null) {
                fos.write(decrypted);
            }
        }
        byte[] finalBytes = cipher.doFinal();
        if (finalBytes != null) {
            fos.write(finalBytes);
        }
        fis.close();
        fos.close();
    }
}

// Clase para cifrado RSA
class RSAEncryption {
    public static byte[] encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }
}

// Clase para generar par de claves RSA
class RSAKeyPairGenerator {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Claves RSA de 2048 bits
        return keyGen.generateKeyPair();
    }
}

// Clase para escribir la clave AES cifrada en un archivo
class KeyFileWriter {
    public static void saveEncryptedAESKey(byte[] encryptedKey, String filePath) throws Exception {
        FileOutputStream fos = new FileOutputStream(filePath);
        fos.write(encryptedKey);
        fos.close();
    }
}
