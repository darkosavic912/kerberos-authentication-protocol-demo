package rs.ac.singidunum;

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES_cipher {
    private static final int IV_SIZE = 16;
    public byte[] encrypt(SecretKey key, byte[] plaintext)  throws  Exception{
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        IvParameterSpec IV = new IvParameterSpec(iv);
        //E
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, IV);
        byte[] ciphertext = c.doFinal(plaintext);

        //Merge iv and ciphertext
        byte[] ivAndCiphertext = new byte[IV_SIZE + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_SIZE);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, IV_SIZE, ciphertext.length);
        return ivAndCiphertext;
    }

    public byte[] decrypt(SecretKey key, byte[] ivAndCiphertext) throws Exception{
        //IV
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_SIZE);
        IvParameterSpec IV = new IvParameterSpec(iv);

        int encryptedSize = ivAndCiphertext.length - IV_SIZE;
        byte[] ciphertext = new byte[encryptedSize];
        System.arraycopy(ivAndCiphertext, IV_SIZE, ciphertext, 0, encryptedSize);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, IV);

        return cipher.doFinal(ciphertext);
    }
}

