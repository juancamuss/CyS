import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DarwinNunez {
    private static String kDatos;

    public static void main(String[] args) {
        // Solicitar la contraseña al usuario
        kDatos = JOptionPane.showInputDialog(null, "Ingrese la contraseña:", "Contraseña requerida", JOptionPane.PLAIN_MESSAGE);

        if (kDatos == null || kDatos.isEmpty()) {
            JOptionPane.showMessageDialog(null, "Contraseña no puede estar vacía", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }

        // Generar y cifrar una clave privada usando AES
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            byte[] privateKey = secretKey.getEncoded();

            // Derivar una clave AES válida a partir de la contraseña
            byte[] salt = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);
            SecretKeySpec keySpec = deriveKeyFromPassword(kDatos, salt);

            // Cifrar la clave privada
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encryptedPrivateKey = cipher.doFinal(privateKey);

            // Mostrar la clave privada cifrada (solo para demostración)
            System.out.println("Clave kDatos: " + kDatos);
            System.out.println("Clave privada cifrada: " + Base64.getEncoder().encodeToString(encryptedPrivateKey));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método para derivar una clave AES válida a partir de una contraseña
    private static SecretKeySpec deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    // Método para generar una clave AES de 128 bits
    public static SecretKey generateAESKey() throws Exception {
        // Crear un generador de claves para el algoritmo AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        // Inicializar el generador para producir claves de 128 bits
        keyGen.init(128); // AES con 128 bits
        // Generar y retornar la clave
        return keyGen.generateKey();
    }

    // // Método para cifrar un archivo utilizando una clave AES
    // public static void encryptFile(String filePath, SecretKey key) throws Exception {
    //     // Crear un objeto Cipher con el modo AES/CBC/PKCS5Padding (AES en modo CBC con padding PKCS5)
    //     Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    //     // Crear un generador de números aleatorios para generar el IV (Vector de Inicialización)
    //     SecureRandom random = new SecureRandom();
    //     byte[] iv = new byte[16]; // AES usa un IV de 16 bytes (128 bits)
    //     random.nextBytes(iv); // Llenar el IV con bytes aleatorios
    //     IvParameterSpec ivSpec = new IvParameterSpec(iv); // Especificar el IV
    //     // Inicializar el Cipher en modo cifrado con la clave y el IV
    //     cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    //     // Referencias a los archivos de entrada (archivo original) y salida (archivo cifrado)
    //     File inputFile = new File(filePath);
    //     File encryptedFile = new File(filePath + ".enc"); // El archivo cifrado tendrá extensión ".enc"

    //     // Leer el archivo de entrada y escribir el archivo cifrado
    //     try (FileInputStream fis = new FileInputStream(inputFile);
    //          FileOutputStream fos = new FileOutputStream(encryptedFile)) {
    //         // Escribir el IV al inicio del archivo cifrado, para usarlo luego en el descifrado
    //         fos.write(iv);
    //         byte[] buffer = new byte[1024]; // Buffer para leer el archivo en bloques de 1024 bytes
    //         int bytesRead;
    //         // Leer el archivo de entrada y cifrarlo por bloques
    //         while ((bytesRead = fis.read(buffer)) != -1) {
    //             // Cifrar el bloque leído
    //             byte[] output = cipher.update(buffer, 0, bytesRead);
    //             // Si el cifrado produjo salida (output), escribirla en el archivo cifrado
    //             if (output != null) fos.write(output);
    //         }
    //         // Finalizar el cifrado y procesar cualquier bloque restante
    //         byte[] output = cipher.doFinal();
    //         // Escribir cualquier dato resultante del método doFinal()
    //         if (output != null) fos.write(output);
    //     }
    // }

    // // Método para descifrar un archivo cifrado utilizando una clave AES
    // public static void decryptFile(String encryptedFilePath, SecretKey key) throws Exception {
    //     // Crear un objeto Cipher con el mismo modo que en el cifrado (AES/CBC/PKCS5Padding)
    //     Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

    //     // Referencias al archivo cifrado (entrada) y al archivo descifrado (salida)
    //     File encryptedFile = new File(encryptedFilePath);
    //     File decryptedFile = new File(encryptedFilePath.replace(".enc", "_decrypted")); // Nombre del archivo descifrado

    //     // Leer el archivo cifrado y escribir el archivo descifrado
    //     try (FileInputStream fis = new FileInputStream(encryptedFile);
    //          FileOutputStream fos = new FileOutputStream(decryptedFile)) {

    //         // Leer el IV que se guardó al inicio del archivo cifrado
    //         byte[] iv = new byte[16];
    //         fis.read(iv); // Leer los primeros 16 bytes, que corresponden al IV
    //         IvParameterSpec ivSpec = new IvParameterSpec(iv); // Especificar el IV leído

    //         // Inicializar el Cipher en modo descifrado con la clave y el IV
    //         cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    //         // Leer el archivo cifrado y descifrarlo por bloques
    //         byte[] buffer = new byte[1024];
    //         int bytesRead;
    //         while ((bytesRead = fis.read(buffer)) != -1) {
    //             // Descifrar el bloque leído
    //             byte[] output = cipher.update(buffer, 0, bytesRead);
    //             // Si el descifrado produjo salida (output), escribirla en el archivo descifrado
    //             if (output != null) fos.write(output);
    //         }
    //         // Finalizar el descifrado y procesar cualquier bloque restante
    //         byte[] output = cipher.doFinal();
    //         // Escribir cualquier dato resultante del método doFinal()
    //         if (output != null) fos.write(output);
    //     }
    // }

    // public static File compressFilesToZip(List<String> filePaths, String zipFilePath) throws IOException {
    //     // Crear un objeto FileOutputStream para el archivo ZIP de salida
    //     try (FileOutputStream fos = new FileOutputStream(zipFilePath);
    //          // Crear un objeto ZipOutputStream a partir del FileOutputStream
    //          ZipOutputStream zos = new ZipOutputStream(fos)) {
    //         // Iterar sobre la lista de archivos
    //         for (String filePath : filePaths) {
    //             File file = new File(filePath);
    //             // Crear un objeto FileInputStream para el archivo actual
    //             try (FileInputStream fis = new FileInputStream(file)) {
    //                 // Crear un objeto ZipEntry con el nombre del archivo y añadirlo al ZipOutputStream
    //                 ZipEntry zipEntry = new ZipEntry(file.getName());
    //                 zos.putNextEntry(zipEntry);

    //                 byte[] buffer = new byte[1024];
    //                 int bytesRead;
    //                 // Leer el contenido del archivo y escribirlo en el ZipOutputStream
    //                 while ((bytesRead = fis.read(buffer)) != -1) {
    //                     zos.write(buffer, 0, bytesRead);
    //                 }
    //                 // Cerrar la entrada del archivo en el ZipOutputStream
    //                 zos.closeEntry();
    //             }
    //         }
    //     }
    //     // Retornar el archivo ZIP comprimido
    //     return new File(zipFilePath);
    // }
}