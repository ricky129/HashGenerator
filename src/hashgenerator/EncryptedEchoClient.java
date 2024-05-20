import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EncryptedEchoClient {

    static String algorithm = "AES/CBC/PKCS5Padding";
    static IvParameterSpec iv;

    public static void KeyGenerator() {
        try {
            // Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for AES-256
            SecretKey secretKey = keyGen.generateKey();

            // Encode the key as Base64
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            // Save the key to a file
            Files.write(Paths.get("key.txt"), encodedKey.getBytes());
            System.out.println("Key saved to key.txt: " + encodedKey);

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String FileToString() throws IOException {
        return new String(Files.readAllBytes(Paths.get("key.txt")));
    }

    public static SecretKey StringToSecretKey(String str) {
        byte[] decodedKey = Base64.getDecoder().decode(str);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static void main(String[] args) {

        KeyGenerator();

        if (args.length != 2) {
            System.out.println("Usage: java EncryptedEchoClient <server-ip> <message>");
            return;
        }

        String serverAddress = args[0];
        int port = 8080;

        try {
            Socket socket = new Socket(serverAddress, port);
            System.out.println("Connected to server at " + serverAddress + " on port " + port);

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Load the secret key and IV from files
            SecretKey key = StringToSecretKey(FileToString());
            iv = generateIv();

            // Encrypt a message
            String message = args[1];
            String encryptedMessage = encrypt(algorithm, message, key, iv);
            String encodedIv = Base64.getEncoder().encodeToString(iv.getIV());

            // Send the encrypted message and IV to the server
            out.println(encryptedMessage + ":" + encodedIv);

            // Read the decrypted message from the server
            String response = in.readLine();
            System.out.println("Received from server: " + response);

            // Close the resources
            in.close();
            out.close();
            socket.close();
        } catch (IOException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException ex) {
            Logger.getLogger(EncryptedEchoClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
