fuentes
marcos
juan
izanfsdfs

el real madrid cf tiene mas roña que el pelo de un gitano

Juan es el mas guapo


dasdadsassdadasdasdasdasddsasd



lllllllllllllllllllllllllllll

// import java.io.*;
// import java.nio.file.*;
// import java.security.SecureRandom;
// import java.util.Base64;

// public class FileEncryptor {

//     private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
//     private static final SecureRandom RANDOM = new SecureRandom();

//     public static void main(String[] args) throws IOException {
//         String inputFilePath = "Prueba.java";
//         String encryptedFilePath = "Prueba_encrypted.java";
//         String keyFilePath = "encryption_key.txt";

//         // Leer el contenido del archivo
//         String content = new String(Files.readAllBytes(Paths.get(inputFilePath)));

//         // Generar una clave aleatoria
//         String key = generateRandomKey(content.length());

//         // Cifrar el contenido del archivo
//         String encryptedContent = encrypt(content, key);

//         // Guardar el contenido cifrado en un nuevo archivo
//         Files.write(Paths.get(encryptedFilePath), encryptedContent.getBytes());

//         // Guardar la clave en un archivo separado
//         Files.write(Paths.get(keyFilePath), key.getBytes());

//         System.out.println("Archivo cifrado y clave guardada.");
//     }

//     private static String generateRandomKey(int length) {
//         StringBuilder key = new StringBuilder(length);
//         for (int i = 0; i < length; i++) {
//             key.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
//         }
//         return key.toString();
//     }

//     private static String encrypt(String content, String key) {
//         StringBuilder encrypted = new StringBuilder(content.length());
//         for (int i = 0; i < content.length(); i++) {
//             encrypted.append((char) (content.charAt(i) ^ key.charAt(i)));
//         }
//         return Base64.getEncoder().encodeToString(encrypted.toString().getBytes());
//     }
// }


public class CompressAndEncrypt {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    public static void main(String[] args) throws IOException {
        String inputFilePath = "Prueba.java";
        String compressedFilePath = "Prueba_compressed.zip";
        String encryptedFilePath = "Prueba_encrypted.java";
        String keyFilePath = "encryption_key.txt";

        // Leer el contenido del archivo
        String content = new String(Files.readAllBytes(Paths.get(inputFilePath)));

        // Comprimir el contenido del archivo
        byte[] compressedContent = compress(content);

        // Generar una clave aleatoria
        String key = generateRandomKey(compressedContent.length);

        // Cifrar el contenido comprimido del archivo
        String encryptedContent = encrypt(compressedContent, key);

        // Guardar el contenido cifrado en un nuevo archivo
        Files.write(Paths.get(encryptedFilePath), encryptedContent.getBytes());

        // Guardar la clave en un archivo separado
        Files.write(Paths.get(keyFilePath), key.getBytes());

        System.out.println("Archivo comprimido, cifrado y clave guardada.");
    }

    private static byte[] compress(String content) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(byteArrayOutputStream)) {
            ZipEntry zipEntry = new ZipEntry("compressedContent");
            zipOutputStream.putNextEntry(zipEntry);
            zipOutputStream.write(content.getBytes());
            zipOutputStream.closeEntry();
        }
        return byteArrayOutputStream.toByteArray();
    }

    private static String generateRandomKey(int length) {
        StringBuilder key = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            key.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return key.toString();
    }

    private static String encrypt(byte[] content, String key) {
        byte[] encrypted = new byte[content.length];
        for (int i = 0; i < content.length; i++) {
            encrypted[i] = (byte) (content[i] ^ key.charAt(i));
        }
        return Base64.getEncoder().encodeToString(encrypted);
    }
}