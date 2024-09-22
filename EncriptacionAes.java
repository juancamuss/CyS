import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESExample {
    public static void main(String[] args) {
        try {
            // Generar una clave AES de 128 bits
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);  // Tamaño de la clave en bits (128, 192 o 256)
            SecretKey secretKey = keyGen.generateKey();

            // Generar un vector de inicialización (IV) seguro y aleatorio
            byte[] iv = new byte[16];  // El tamaño del IV debe ser de 16 bytes para AES
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);  // Generar valores aleatorios y llenar el IV
            
            // Convertir el IV a IvParameterSpec, que es necesario para ciertos modos de operación de cifrado
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Crear una instancia del cifrador AES en modo CBC con relleno PKCS5
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Inicializar el cifrador en modo ENCRYPT_MODE con la clave secreta y el IV
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            // Ejemplo de un mensaje a cifrar
            String mensaje = "Este es un mensaje secreto";

            // Cifrar el mensaje
            byte[] mensajeCifrado = cipher.doFinal(mensaje.getBytes("UTF-8"));

            // Imprimir el resultado cifrado (en bytes)
            System.out.println("Mensaje cifrado (en bytes):");
            for (byte b : mensajeCifrado) {
                System.out.print(b + " ");
            }

            // Mostrar el IV generado
            System.out.println("\nIV utilizado (en bytes):");
            for (byte b : iv) {
                System.out.print(b + " ");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
