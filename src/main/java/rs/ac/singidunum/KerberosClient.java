package rs.ac.singidunum;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KerberosClient {
    private static final Logger LOGGER = Logger.getLogger(KerberosClient.class.getName());

    public static void main(String[] args) {
        String serverName = "localhost";
        int port = 8088;
        System.out.println("Connecting to server " + serverName + ":" + port);

        try (Socket client = new Socket(serverName, port);
             DataOutputStream out = new DataOutputStream(client.getOutputStream());
             DataInputStream in = new DataInputStream(client.getInputStream())) {

            System.out.println("Connection established: " + client.getRemoteSocketAddress());

            // 1. Alice sends TGT request
            String passwordAlice = "topsecret";
            String message = "Alice";
            out.writeUTF(message);
            System.out.println("TGT Request sent for user: " + message);

            // 1.2. Compute password hash (SHA-256)
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] passwordHash = md.digest(passwordAlice.getBytes(StandardCharsets.UTF_8));

            // 1.3. Regenerate client secret key (Ka) from password hash (first 16 bytes for AES-128)
            byte[] keyMaterial = Arrays.copyOfRange(passwordHash, 0, 16);
            SecretKey userKeyKa = new SecretKeySpec(keyMaterial, "AES");

            // 1.4. Alice receives encrypted payload containing Session Key (Sa) and TGT
            byte[] saTgtEncrypted = Base64.getDecoder().decode(in.readUTF());

            // 1.5. Decrypt SA+TGT payload using Ka (Note: AES_cipher decrypt handles internal IV extraction)
            // After this Ka is not used anymore
            byte[] saTgt = new AES_cipher().decrypt(userKeyKa, saTgtEncrypted);

            // 1.6. Extract encrypted Session Key (Sa) and encrypted TGT from decrypted byte stream
            ByteArrayInputStream bisSaTgt = new ByteArrayInputStream(saTgt);
            DataInputStream disSaTgt = new DataInputStream(bisSaTgt);

            int lenSa = disSaTgt.readInt();
            byte[] saEncryptedBytes = new byte[lenSa];
            disSaTgt.readFully(saEncryptedBytes);

            int lenTgt = disSaTgt.readInt();
            byte[] encryptedTgt = new byte[lenTgt];
            disSaTgt.readFully(encryptedTgt);

            // 1.7. Alice decrypt ciphertext and take session key
            byte [] saBytes = new AES_cipher().decrypt(userKeyKa, saEncryptedBytes);
            SecretKey saKey = new SecretKeySpec(saBytes, "AES");

            // 1.7. Alice prepares a request to access data (TGT + Requested File Name + Authenticator)
            LocalDateTime now = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy,HH:mm:ss");
            String timestamp = now.format(formatter);
            System.out.println("Current timestamp: " + timestamp);

            // 1.8. Create Authenticator encrypted with Session Key (Sa)
            byte[] authenticator = new AES_cipher().encrypt(saKey, timestamp.getBytes(StandardCharsets.UTF_8));
            byte[] fileNameBytes = "Database.enc".getBytes(StandardCharsets.UTF_8);

            // 1.9. Create request: [Encrypted TGT] + [Requested File Name] + [Encrypted Authenticator]
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);

            dos.writeInt(encryptedTgt.length);
            dos.write(encryptedTgt);

            dos.writeInt(fileNameBytes.length);
            dos.write(fileNameBytes);

            dos.writeInt(authenticator.length);
            dos.write(authenticator);

            byte[] packetTGTFileAuthenticator = bos.toByteArray();

            // 2. Send request to server/KDC
            out.writeUTF(Base64.getEncoder().encodeToString(packetTGTFileAuthenticator));

            String response = in.readUTF();

            //2.1 If authenticator is not valid server will return proper string
            if(response.startsWith("REJECTED: stale authenticator")) {
                System.out.println("Invalid authenticator!");
                return;
            }

            // 2.1. Receive response ticket TGT encrypted with Session Key (Sa)
            byte[] responseEncrypted = Base64.getDecoder().decode(response);

            // 2.2. Decrypt with Session key Sa
            byte[] decryptedResponse = new AES_cipher().decrypt(saKey, responseEncrypted);

            // 2.3. Extract form TGT  target file path and Service Session Key (Kab)
            ByteArrayInputStream bisResponse = new ByteArrayInputStream(decryptedResponse);
            DataInputStream disResponse = new DataInputStream(bisResponse);

            int lenTargetFile = disResponse.readInt();
            byte[] targetFileNameBytes = new byte[lenTargetFile];
            disResponse.readFully(targetFileNameBytes);

            int lenKab = disResponse.readInt();
            byte[] kabBytes = new byte[lenKab];
            disResponse.readFully(kabBytes);

            // 2.4. Read encrypted file from disk and decrypt data it using Kab
            SecretKey kabKey = new SecretKeySpec(kabBytes, "AES");
            byte[] encryptedFile = Files.readAllBytes(Paths.get(new String(targetFileNameBytes, StandardCharsets.UTF_8)));
            byte[] readFromFile = new AES_cipher().decrypt(kabKey, encryptedFile);

            System.out.println("Decrypted file content: " + new String(readFromFile, StandardCharsets.UTF_8));

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in client communication or cryptographic operations", e);
        }
        System.out.println("Connection closed.");
    }
}