
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class TripleDESTest {

    static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static String getHash(String password, String salt) throws Exception {
        try {
            String input = password + salt;
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] out = md.digest(input.getBytes("UTF-8"));
            return bytesToHex(out);
        } catch (Exception e) {
            throw new Exception("ERROR al hacer hash", e);
        }
    }
    
    private static String padStrWithDirection(String str, Character c, int len, Boolean left) {
        StringBuilder result = new StringBuilder();
        
        if (!left) result.append(str);
        for (int i = 0; i < len - str.length(); i++) {
            result.append(c);
        }
        if (left) result.append(str);
            
        return result.toString();    
    }

    private static String reves(String objeto) {
        StringBuilder sb = new StringBuilder(objeto);
        return sb.reverse().toString();
    }

    public static String bytesToHex(byte[] buf) {
        char[] chars = new char[2 * buf.length];
        for (int i = 0; i < buf.length; ++i) {
            chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
        }
        return new String(chars);
    }

    public static byte[] hexToBytes(String str) {
        if (str == null) {
            return null;
        } else if (str.length() < 2) {
            return null;
        } else {
            int len = str.length() / 2;
            byte[] buffer = new byte[len];
            for (int i = 0; i < len; i++) {
                buffer[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);
            }
            return buffer;
        }
    }

    private static byte[] concatByteArray(byte[] a, byte[] b) throws IOException {
        byte[] c = new byte[a.length + b.length];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(a);
        outputStream.write(b);

        c = outputStream.toByteArray();
        return c;
    }

    /**
     * El codigo generar el SecretKey debe tener 24 caracteres, si no se 
     * puede rellenar a la izquierda o la derecha o en su defecto generar un digest
     * MD5 o SHA1 y tomar 24 caracteres a partir del principio o del final
     *
     * @author alienware
     */
    public static String encrypt(String message, String codigo) throws Exception {
        String clave = padStrWithDirection(codigo,'0', 24, false);
        
        final SecretKey key = new SecretKeySpec(clave.getBytes("utf-8"), "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        final byte[] plainTextBytes = message.getBytes("utf-8");
        final byte[] cipherText = cipher.doFinal(plainTextBytes);

        final String encodedCipherText = new Base64().encodeToString(cipherText);
        return encodedCipherText;
    }
    public static String decrypt(String message, String codigo) throws Exception {
        String clave = padStrWithDirection(codigo,'0', 24, false);
        
        final byte[] encData = new Base64().decode(message);
        final SecretKey key = new SecretKeySpec(clave.getBytes(), "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);
        final byte[] plainText = decipher.doFinal(encData);
        return new String(plainText, "UTF-8");
    }

    /**
     * Genera aleatoriamente un password de 8 caracteres el cual se le hace un
     * digest md5 el cual se perturba creando un SHA1 del cual se toman 24 caracteres de 
     * los 40 que se generan.
     * 
     * @param message
     * @return
     * @throws Exception 
     */
    public static String encrypt(String message) throws Exception {
        String clave = PasswordGenerator.getPassword(8,"");
        final MessageDigest md = MessageDigest.getInstance("md5");
        String hash = getHash(clave, reves(clave));
        final byte[] digestOfPassword = md.digest(hash.getBytes("utf-8"));
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }

        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        final byte[] plainTextBytes = message.getBytes("utf-8");
        final byte[] cipherText = cipher.doFinal(plainTextBytes);

        final byte[] toConvert = concatByteArray(cipherText, clave.getBytes("utf-8"));

        final String encodedCipherText = new Base64().encodeToString(toConvert);
        return encodedCipherText;
    }

    public static String decrypt(String message) throws Exception {
        final byte[] encData = new Base64().decode(message);

        String clave = new String(Arrays.copyOfRange(encData, encData.length - 8, encData.length));

        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest(getHash(clave, reves(clave)).getBytes("utf-8"));
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8;) {
            keyBytes[k++] = keyBytes[j++];
        }

        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);

        final byte[] cipherText = Arrays.copyOf(encData, encData.length - 8);
        final byte[] plainText = decipher.doFinal(cipherText);

        return new String(plainText, "UTF-8");
    }

    public static void main(String[] args) throws Exception {

        System.out.println(padStrWithDirection("ABCDEF", '0', 20, false));
        
        String text = "cadena con ñáé";

        String codedtext = TripleDESTest.encrypt(text);
        String decodedtext = TripleDESTest.decrypt(codedtext);

        System.out.println(codedtext);
        System.out.println(decodedtext);
    }
}