
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author ROG
 */
public class Blowfish {
    
    private static Base64 base64 = new Base64(true);
    
    public static String sha256(String base) {
    try{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(base.getBytes("UTF-8"));
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    } catch(Exception ex){
       throw new RuntimeException(ex);
    }
}
    
    public static String encrypt(String strKey, String msg) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, Exception {
        strKey = (strKey.length() > 16) ? strKey.substring(0,15) : strKey;
        SecretKeySpec key = new SecretKeySpec(strKey.getBytes("UTF-8"), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        if (cipher == null || key == null) {
            throw new Exception("Invalid key or cypher");
        }
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return base64.encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));
    }

    public static String decrypt(String strKey, String msg) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        strKey = (strKey.length() > 16) ? strKey.substring(0,15) : strKey;
        SecretKeySpec key = new SecretKeySpec(strKey.getBytes("UTF-8"), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(base64.decodeBase64(msg));
        return new String(decrypted);
    }
    
    public static void main(String[] a) throws UnsupportedEncodingException {
        try {
            String key = "1234";
            String mensaje = "Hola mundo";
            
            String cod = encrypt(sha256(key), mensaje);
            String dec = decrypt(sha256(key),  cod);
            
            System.out.println(sha256(key)+" "+cod+" "+dec);
            
         
        } catch (Exception ex) {
            System.err.println(ex.toString());
        }
        

        
    }
}
