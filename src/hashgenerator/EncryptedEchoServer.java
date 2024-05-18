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
import java.util.logging.Level;
import java.util.logging.Logger;
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
    String message;
    static String algorithm = "AES/CBC/PKCS5Padding";
    static IvParameterSpec iv = generateIv();
    
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
    
    public static String FileToString() throws IOException{
        String content = new String(Files.readAllBytes(Paths.get("key.txt")));
        return content;
    }
    
    public static String SecretKeyToString(SecretKey secretkey){
        try {
            secretkey = KeyGenerator.getInstance(algorithm).generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(EncryptedEchoServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        String encodedKey = Base64.getEncoder().encodeToString(secretkey.getEncoded());
        return encodedKey;
    }
    
    public static SecretKey StringToSecretKey(String str){
        byte[] decodedKey = Base64.getDecoder().decode(str);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm);
        return originalKey;
    }
    
    public static void main(String[] args){

        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("Server in ascolto sulla porta " + 8080);

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("Nuova connessione da " + clientSocket.getInetAddress().getHostAddress());
                    
                    PrintWriter out;
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {
                        out = new PrintWriter(clientSocket.getOutputStream(), true);
                    }
                        SecretKey key = StringToSecretKey(FileToString());
                    try {
                        message = decrypt(algorithm, FileToString(), key, iv);
                    } catch (NoSuchPaddingException ex) {
                        Logger.getLogger(EncryptedEchoServer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(EncryptedEchoServer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidAlgorithmParameterException ex) {
                        Logger.getLogger(EncryptedEchoServer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeyException ex) {
                        Logger.getLogger(EncryptedEchoServer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        Logger.getLogger(EncryptedEchoServer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        Logger.getLogger(EncryptedEchoServer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    out.close();
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
}
}

    /*

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
    
    private static String loadSecretKeyFromFile() throws Exception {
        // Read the byte array from the file
        byte[] keyBytes = Files.readAllBytes(Paths.get("key.txt"));

        // Reconstruct the SecretKey from the byte array
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        return byteArrayToString(secretKey.getEncoded());
    }

    public static SecretKey ByteToSecretKey(byte[] bt){
        return new SecretKeySpec(bt, algorithm);
    }

    private static String byteArrayToString(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray)
            sb.append(b).append(" ");
        return sb.toString();
    }
    
    public static byte[] StringToByte(String str){
        
        // Convert string to byte array using a custom character encoding (e.g., US-ASCII)
        Charset charset = Charset.forName("US-ASCII"); // Using US-ASCII encoding
        byte[] byteArray = str.getBytes(charset);
        
        return byteArray;
    }
*/