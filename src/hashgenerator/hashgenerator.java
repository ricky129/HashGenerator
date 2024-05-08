package hashgenerator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author ricky
 */
public class hashgenerator {

    //metodo per generare l'hash SHA-256 di una stringa
    public String stringToSHA2(String input) {
        try {
            //ottieni un'istanza di MessageDigest per l'algoritmo SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            //Calcola l'hash della stringa di input
            byte[] hashBytes = digest.digest(input.getBytes());

            //Converte l'array di byte dell'hash in una rappresentazione esadecimale
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < hashBytes.length; i++) {
                byte hashByte = hashBytes[i];
                //Calcoliamo la rappresentazione esadecimale hex di hashByte come nel codice originale
                String hex = Integer.toHexString(0xff & hashByte);
                /*
                Se la lunghezza della stringa hex è 1 (cioè rappresenta un solo carattere 
                esadecimale), aggiungiamo uno zero all'inizio per assicurarci che ciascun 
                byte sia rappresentato da due caratteri esadecimali
                 */
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public String Connect(String[] args){
        String message = null;
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
                        message = in.readLine();
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
        return message;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        if (args.length == 0) {
            System.err.println("Usage: java HashGeneratorServer <message>");
            return;
        }
        
        hashgenerator HG1 = new hashgenerator();

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
                            out.println(HG1.stringToSHA2(message));
                        else
                            System.out.println("Errore, il messaggio è vuoto.");
                    }
                    out.close();
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(hashgenerator.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
