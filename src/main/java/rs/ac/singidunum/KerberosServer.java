package rs.ac.singidunum;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KerberosServer {
    private static final Logger LOGGER = Logger.getLogger(KerberosServer.class.getName());

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 1.3. Generate KDC Symmetric Master Key, it is generated only once, not for every connection
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey kdcMasterKey = kg.generateKey();
        int port = 8088;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started. Waiting for client...");

            while (true) {

                try (Socket server = serverSocket.accept();
                     DataInputStream in = new DataInputStream(server.getInputStream());
                     DataOutputStream out = new DataOutputStream(server.getOutputStream())) {

                    System.out.println("Client connected: " + server.getRemoteSocketAddress());

                    // 1. Server receives TGT request
                    String messageClient = in.readUTF();
                    System.out.println("TGT request received from user: " + messageClient);
                    String passwordActiveDirectory = "topsecret";

                    // 1.1 KDC send session key Sa and TGT, all encrypted with inicialised key kA from password hash
                    // Compute hash from Active Directory user password
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    md.update(passwordActiveDirectory.getBytes(StandardCharsets.UTF_8));
                    byte[] passwordHash = md.digest();

                    // 1.2. Derive Ka key (first 16 bytes for AES-128)
                    byte[] keyMaterial = Arrays.copyOfRange(passwordHash, 0, 16);
                    SecretKey userKeyKa = new SecretKeySpec(keyMaterial, "AES");

                    // 1.4. Generate Session Key (Sa)
                    byte[] saBytes = new byte[16];
                    new SecureRandom().nextBytes(saBytes);

                    // 1.5. Encrypt session key Sa
                    byte [] encryptedSa = new AES_cipher().encrypt(userKeyKa,saBytes);

                    // 1.6. Create TGT payload: [Session Key Sa] + [Client Id]/ Permanently destroyed Sa key after creating TGT
                    byte[] clientIdBytes = messageClient.getBytes(StandardCharsets.UTF_8);
                    byte[] tgtPayload = new byte[saBytes.length + clientIdBytes.length];
                    System.arraycopy(saBytes, 0, tgtPayload, 0, saBytes.length);
                    System.arraycopy(clientIdBytes, 0, tgtPayload, saBytes.length, clientIdBytes.length);

                    // 1.6. Encrypt TGT using KDC Master Key
                    byte[] encryptedTgt = new AES_cipher().encrypt(kdcMasterKey, tgtPayload);

                    // 1.7. Merge [Session Key Sa] + [Encrypted TGT] into a single structured byte array
                    ByteArrayOutputStream bosSaTgt = new ByteArrayOutputStream();
                    DataOutputStream dosSaTgt = new DataOutputStream(bosSaTgt);

                    dosSaTgt.writeInt(encryptedSa.length);
                    dosSaTgt.write(encryptedSa);

                    dosSaTgt.writeInt(encryptedTgt.length);
                    dosSaTgt.write(encryptedTgt);

                    byte[] saTgtPayload = bosSaTgt.toByteArray();

                    // 1.8. Encrypt combined payload with client secret key (Ka)/ (Sa + TGT)
                    byte[] encryptedSaTgtPayload = new AES_cipher().encrypt(userKeyKa, saTgtPayload);

                    // 1.9. Send response (encrypted Sa + TGT) back to Client
                    out.writeUTF(Base64.getEncoder().encodeToString(encryptedSaTgtPayload));

                    // 2. KDC receives access request from Client
                    byte[] packetTGTFileAuthenticator = Base64.getDecoder().decode(in.readUTF());

                    // 2.1.cTakes from packet TGT, file name and authenticator
                    ByteArrayInputStream bis = new ByteArrayInputStream(packetTGTFileAuthenticator);
                    DataInputStream dis = new DataInputStream(bis);

                    int lenTgt = dis.readInt();
                    byte[] clientEncryptedTgt = new byte[lenTgt];
                    dis.readFully(clientEncryptedTgt);

                    int lenFile = dis.readInt();
                    byte[] requestedFileNameBytes = new byte[lenFile];
                    dis.readFully(requestedFileNameBytes);

                    int lenAuth = dis.readInt();
                    byte[] authenticatorBytes = new byte[lenAuth];
                    dis.readFully(authenticatorBytes);

                    // 2.2. Kerberos decrypts with KDC TGT to recover Session Key (Sa)
                    byte[] decryptedTgtPayload = new AES_cipher().decrypt(kdcMasterKey, clientEncryptedTgt);

                    // 2.3. Extract Session Key (Sa) from decrypted TGT
                    byte[] saFromTgt = Arrays.copyOfRange(decryptedTgtPayload, 0, 16);
                    SecretKey saClientKey = new SecretKeySpec(saFromTgt, "AES");

                    // 2.4. KDC decrypts Authenticator using Session Key (Sa) to verify request freshness
                    byte[] timestampBytes = new AES_cipher().decrypt(saClientKey, authenticatorBytes);
                    System.out.println("Authenticator timestamp (Valid): " + new String(timestampBytes, StandardCharsets.UTF_8));

                    // 2.5. Parsing timestamp (prevent replay attack) to LocalDateTime
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy,HH:mm:ss");
                    LocalDateTime dateTime = LocalDateTime.parse(new String(timestampBytes, StandardCharsets.UTF_8), formatter);
                    LocalDateTime localTimeNow = LocalDateTime.now();
                    Duration difference = Duration.between(dateTime, localTimeNow);
                    long seconds = Math.abs(difference.getSeconds());
                    if(seconds > 60){
                        out.writeUTF(("REJECTED: stale authenticator"));
                        System.out.println("Rejected invalid authenticator!");
                        continue;
                    }

                    // 2.5. Prepare target data file on server
                    String fileName = new String(requestedFileNameBytes, StandardCharsets.UTF_8);
                    try (FileOutputStream fos = new FileOutputStream(fileName)) {
                        fos.write("Data content for database - Kerberos protocol implementation".getBytes(StandardCharsets.UTF_8));
                    }

                    // 2.6. KDC generates Service Session Key (Kab)
                    byte[] kabBytes = new byte[16];
                    new SecureRandom().nextBytes(kabBytes);
                    SecretKey kabKey = new SecretKeySpec(kabBytes, "AES");

                    // 2.7. Encrypt file content with Kab key and save back to file
                    byte[] rawFileBytes = Files.readAllBytes(Paths.get(fileName));
                    byte[] encryptedFileBytes = new AES_cipher().encrypt(kabKey, rawFileBytes);
                    Files.write(Paths.get(fileName), encryptedFileBytes);

                    //Kerberos dont store key in database, it takes it from TGT
                    // 2.8. Create service ticket containing [Target File Name] + [Kab Key]
                    ByteArrayOutputStream bosReply = new ByteArrayOutputStream();
                    DataOutputStream dosReply = new DataOutputStream(bosReply);

                    dosReply.writeInt(requestedFileNameBytes.length);
                    dosReply.write(requestedFileNameBytes);

                    dosReply.writeInt(kabBytes.length);
                    dosReply.write(kabBytes);

                    byte[] replyTicket = bosReply.toByteArray();

                    // 2.9. Encrypt reply ticket with Session Key (Sa)
                    byte[] encryptedReplyTicket = new AES_cipher().encrypt(saClientKey, replyTicket);

                    // 3. Send encrypted ticket back to Client
                    out.writeUTF(Base64.getEncoder().encodeToString(encryptedReplyTicket));

                    System.out.println("Connection closed.\n");
                } catch (Exception e) {
                    // Communication failure with ONE client does not crash the server
                    LOGGER.log(Level.WARNING, "Error processing client connection", e);
                }
            }
        } catch (Exception e) {
            // Failure of ServerSocket itself (e.g., port 8088 is occupied)
            LOGGER.log(Level.SEVERE, "Critical error: Server failed to start", e);
        }
    }
}