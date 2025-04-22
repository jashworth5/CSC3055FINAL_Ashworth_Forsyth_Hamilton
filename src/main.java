import java.net.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.math.BigInteger;

public class main {
    public static void main(String[] args) throws Exception {
        String password = "password123";
        String message = "Hello, this is a secret message!";
        String hash = SHA256(message);
        String encrypted = encrypt(hash, password);
        String decrypted = decrypt(encrypted, password);
        System.out.println("Decrypted: " + decrypted);

        Socket s = new Socket("localhost", 8000);
        DataOutputStream dout = new DataOutputStream(s.getOutputStream());
        dout.writeUTF(encrypted);
        dout.flush();
        dout.close();
        s.close();
    }

    public static String SHA256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(input.getBytes());
        return new BigInteger(1, md.digest()).toString(16);
    }

    public static String encrypt(String message, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")));
    }

    public static String decrypt(String encrypted, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)), "UTF-8");
    }
}
