package hashgenerator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author ricky
 */
public class AESCrypto {

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /*
     * The Initialization Vector (IV) is a parameter used to ensure that encrypted 
     * data remains unique, even when the same plaintext is encrypted multiple times with the same key.
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
    File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
    NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {
    
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    FileOutputStream outputStream;
    
        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            outputStream = new FileOutputStream(outputFile);
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null)
                    outputStream.write(output);
            }       
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null)
                outputStream.write(outputBytes);
            }
    outputStream.close();
}
    
    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
    File inputFile, File outputFile) throws IOException,
    NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {
        
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.DECRYPT_MODE, key, iv);

    try (FileInputStream inputStream = new FileInputStream(inputFile);
         FileOutputStream outputStream = new FileOutputStream(outputFile)) {

        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            /*
            The Cipher.update() method processes a portion of the input data with the specified cipher 
            operation (encrypt or decrypt) and returns the processed output.
            */
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null)
                outputStream.write(output);
        }

        /*
        After processing all the input data (either through the loop or reaching the end of the 
        input stream), you call Cipher.doFinal(). This method finalizes the decryption process 
        and handles any remaining data (like the last block with padding, if applicable). 
        */
        byte[] finalOutput = cipher.doFinal();
        if (finalOutput != null)
            outputStream.write(finalOutput);
    }
}
    public static void readFile(File input){
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new FileReader(input));
            String line;

            while ((line = reader.readLine()) != null)
                System.out.println(line);
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (reader != null)
                try {
                    reader.close();
                } catch (IOException e) {
                    System.err.println("Error closing the file: " + e.getMessage());
                }
        }
    }
    

        
    }
    /*
    public String Connect(String[] args){
        
        if (args.length == 0) {
            System.err.println("Usage: java HashGeneratorServer <message>");
            return null;
        }

        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("Server in ascolto sulla porta " + 8080);

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("Nuova connessione da " + clientSocket.getInetAddress().getHostAddress());
                    
                    PrintWriter out;
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {
                        out = new PrintWriter(clientSocket.getOutputStream(), true);
                        String message = in.readLine();
                        if(message != null)
                            out.println(message);//modificare
                        else
                            System.out.println("Errore, il messaggio è vuoto.");
                    }
                    out.close();
                }
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {}
*/
