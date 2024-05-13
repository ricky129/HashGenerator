import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ricky
 */
public class EncryptedEchoServer {
    
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
    
    public static String make16(String message) {
        while(message.length()%16!=0)
            message+="_";
        return message;
    }
    
    public static void saveOnFile(String key){

        // Define the file path
        String filePath = "key.txt";

        // Use try-with-resources to ensure the BufferedWriter is properly closed
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // Write the message to the file
            writer.write(key);

            System.out.println("Message has been written to the file: " + filePath);
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
    }
    
    private static void saveSecretKeyToFile(SecretKey secretKey) throws Exception {
        // Convert SecretKey to byte array
        byte[] keyBytes = secretKey.getEncoded();

        try ( // Write the byte array to a file
                FileOutputStream fos = new FileOutputStream("key.txt")) {
            fos.write(keyBytes);
        }
    }
    
    private static SecretKey loadSecretKeyFromFile() throws Exception {
        // Read the byte array from the file
        byte[] keyBytes = Files.readAllBytes(Paths.get("key.txt"));

        // Reconstruct the SecretKey from the byte array
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES"); // Assuming AES algorithm

        return secretKey;
    }
    
    public static String getKey(){
        String filePath = "key.txt", key = null;
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            
            while(reader.readLine() != null)
                key+=reader.readLine();
            
        } catch (IOException e) {
            System.out.println("Error reading from file: " + e.getMessage());
        }
        return key;
    }
    
    public static IvParameterSpec generateIv() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return new IvParameterSpec(iv);
}
    
    public static String encrypt(String algorithm, String input, SecretKey key,
    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {
    
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] cipherText = cipher.doFinal(input.getBytes());
    return Base64.getEncoder()
        .encodeToString(cipherText);
    }
    
    public static String decrypt(String algorithm, String cipherText, SecretKey key,
    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {
    
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    byte[] plainText = cipher.doFinal(Base64.getDecoder()
        .decode(cipherText));
    return new String(plainText);
    }
    
    private static String byteArrayToString(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            sb.append(b).append(" ");
        }
        return sb.toString();
    }
    
    public static byte[] StringToByte(String str){
        
        // Convert string to byte array using a custom character encoding (e.g., US-ASCII)
        Charset charset = Charset.forName("US-ASCII"); // Using US-ASCII encoding
        byte[] byteArray = str.getBytes(charset);
        
        return byteArray;
    }
    
    public static void main(String[] args){
        Scanner s = new Scanner(System.in);
        String message, algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec iv = generateIv();
        SecretKey key = null;
            
        if (args.length != 2) {
            System.err.println("Usage: java HashGeneratorServer <key> (first time) || java HashGeneratorServer <message>");
            return;
        }

        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("Server in ascolto sulla porta " + 8080);

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("Nuova connessione da " + clientSocket.getInetAddress().getHostAddress());
                    
                    PrintWriter out;
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {
                        out = new PrintWriter(clientSocket.getOutputStream(), true);
                        if(key == null) {
                            key = StringToByte(args[0]);
                            
                            System.out.println("Invia il tuo primo messaggio.");
                            message = s.nextLine();
                            if(message != null)
                                
                            else
                            System.out.println("Errore, il messaggio è vuoto.");
                        }
                        else {
                        System.out.println(args[0]);
                        System.out.println("Scrivi il tuo messaggio.");
                        message = s.nextLine();
                        if(message != null)
                            out.println(message);
                        else
                            System.out.println("Errore, il messaggio è vuoto.");
                        }
                    }
                    out.close();
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
}
}