import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;

public class DarwinNunez {
    private static String kDatos;
    private static final String PRIVATE_KEY_FILE = "privateKey.enc";
    private static final String PUBLIC_KEY_FILE = "publicKey.enc";
    
    public static void main(String[] args) {
        // Solicitar la contraseña al usuario
        kDatos = JOptionPane.showInputDialog(null, "Ingrese la contraseña:", "Contraseña requerida", JOptionPane.PLAIN_MESSAGE);

        if (kDatos == null || kDatos.isEmpty()) {
            JOptionPane.showMessageDialog(null, "Contraseña no puede estar vacía", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }

        try {
            // Verificar si las claves privadas y públicas existen
            File privateKeyFile = new File(PRIVATE_KEY_FILE);
            File publicKeyFile = new File(PUBLIC_KEY_FILE);

            if (privateKeyFile.exists() && publicKeyFile.exists()) {
                // Intentar descifrar la clave privada usando la kDatos
                byte[] encryptedPrivateKey = readFromFile(PRIVATE_KEY_FILE);
                byte[] salt = new byte[16]; // Suponemos que el salt fue guardado
                byte[] iv = new byte[16];   // Suponemos que el IV fue guardado
                byte[] encryptedKey = new byte[encryptedPrivateKey.length - 32]; // Salto y IV ya no cuentan
                System.arraycopy(encryptedPrivateKey, 0, salt, 0, 16);
                System.arraycopy(encryptedPrivateKey, 16, iv, 0, 16);
                System.arraycopy(encryptedPrivateKey, 32, encryptedKey, 0, encryptedKey.length);

                SecretKeySpec keySpec = deriveKeyFromPassword(kDatos, salt);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

                try {
                    byte[] decryptedPrivateKey = cipher.doFinal(encryptedKey);
                    System.out.println("Clave privada descifrada: " + Base64.getEncoder().encodeToString(decryptedPrivateKey));
                    // Pasar a la siguiente ventana
                    JOptionPane.showMessageDialog(null, "Acceso concedido", "Éxito", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(null, "Error al descifrar clave privada", "Error", JOptionPane.ERROR_MESSAGE);
                    e.printStackTrace();
                }
            } else {
                // Generar claves y cifrarlas
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
                keyPairGen.initialize(2048);
                KeyPair keyPair = keyPairGen.generateKeyPair();
                
                // Guardar la clave pública en texto plano para uso posterior
                byte[] publicKey = keyPair.getPublic().getEncoded();
                writeToFile(PUBLIC_KEY_FILE, publicKey);

                // Cifrar la clave privada usando AES y la contraseña kDatos
                byte[] privateKey = keyPair.getPrivate().getEncoded();
                byte[] salt = new byte[16];
                SecureRandom random = new SecureRandom();
                random.nextBytes(salt);
                SecretKeySpec keySpec = deriveKeyFromPassword(kDatos, salt);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[16];
                random.nextBytes(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
                byte[] encryptedPrivateKey = cipher.doFinal(privateKey);

                // Guardar salt, IV y clave privada cifrada en un archivo
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(salt);
                outputStream.write(iv);
                outputStream.write(encryptedPrivateKey);
                writeToFile(PRIVATE_KEY_FILE, outputStream.toByteArray());

                JOptionPane.showMessageDialog(null, "Claves generadas y guardadas correctamente", "Éxito", JOptionPane.INFORMATION_MESSAGE);
            }
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

    // Método para leer datos de un archivo
    private static byte[] readFromFile(String filePath) throws IOException {
        File file = new File(filePath);
        byte[] data = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(data);
        }
        return data;
    }

    // Método para escribir datos a un archivo
    private static void writeToFile(String filePath, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);
        }
    }
}
