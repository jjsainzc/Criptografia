
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author JAVA
 */
public class EjemploSimetrico {

    private Cipher ecipher;
    private Cipher dcipher;

    public EjemploSimetrico() {
    }

    public EjemploSimetrico(String fraseSecreta) {
        // 8-bytes Salt fijo para el PBEParameterSpec
        byte[] salt = {
            (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
            (byte) 0x56, (byte) 0x34, (byte) 0xE3, (byte) 0x03
        };

        // Conteo iterativo y construccion de salt invertido y alternado
        String salt1 = invertidor(reves(fraseSecreta));
        int iterationCount = (int) ( Math.pow(fraseSecreta.length(),3) / 2);

        try {

            KeySpec keySpec = new PBEKeySpec(fraseSecreta.toCharArray(), salt1.getBytes(), iterationCount);
            SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);

            ecipher = Cipher.getInstance(key.getAlgorithm());
            dcipher = Cipher.getInstance(key.getAlgorithm());

            // Preparar parametros para los algoritmos
            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

            ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
            dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("EXCEPTION: InvalidAlgorithmParameterException");
        } catch (InvalidKeySpecException e) {
            System.out.println("EXCEPTION: InvalidKeySpecException");
        } catch (NoSuchPaddingException e) {
            System.out.println("EXCEPTION: NoSuchPaddingException");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("EXCEPTION: NoSuchAlgorithmException");
        } catch (InvalidKeyException e) {
            System.out.println("EXCEPTION: InvalidKeyException");
        }


    }

    public EjemploSimetrico(SecretKey key, String algorithm) {
        try {
            ecipher = Cipher.getInstance(algorithm);
            dcipher = Cipher.getInstance(algorithm);
            ecipher.init(Cipher.ENCRYPT_MODE, key);
            dcipher.init(Cipher.DECRYPT_MODE, key);
        } catch (NoSuchPaddingException e) {
            System.out.println("EXCEPTION: NoSuchPaddingException");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("EXCEPTION: NoSuchAlgorithmException");
        } catch (InvalidKeyException e) {
            System.out.println("EXCEPTION: InvalidKeyException");
        }
    }

    public String invertidor(String invertirTexto) {
        char[] inverted = invertirTexto.toCharArray();

        for (int i = 0; i < invertirTexto.length(); i++) {
            if (invertirTexto.codePointAt(i) >= 65 && invertirTexto.codePointAt(i) <= 90) {
                inverted[i] = Character.toLowerCase(inverted[i]);
            } else {
                if (invertirTexto.codePointAt(i) >= 97 && invertirTexto.codePointAt(i) <= 122) {
                    inverted[i] = Character.toUpperCase(inverted[i]);
                }
            }
        }
        return String.valueOf(inverted); 
    }
    
    

    private String reves(String objeto) {
        StringBuffer sb = new StringBuffer(objeto);
        return sb.reverse().toString();
    }

    public String encrypt(String str) {
        try {
            // Preparar variable
            byte[] utf8 = str.getBytes("UTF8");

            // Encriptar
            byte[] enc = ecipher.doFinal(utf8);

            // Convertir a base64
            return new sun.misc.BASE64Encoder().encode(enc);

        } catch (BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        } catch (IOException e) {
        }
        return null;
    }

    public String decrypt(String str) {

        try {

            // Decodificar el base64 del encriptado
            byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);

            // Decodifcar el encriptado
            byte[] utf8 = dcipher.doFinal(dec);

            // Convertir a cadena
            return new String(utf8, "UTF8");

        } catch (BadPaddingException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (UnsupportedEncodingException e) {
        } catch (IOException e) {
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        SecretKey blowfishKey = KeyGenerator.getInstance("Blowfish").generateKey();

        ObjectOutputStream oout = new ObjectOutputStream(new FileOutputStream("archivo.key"));
        try {
            oout.writeObject(blowfishKey);
        } finally {
            oout.close();
        }

        ObjectInputStream oin = new ObjectInputStream(new FileInputStream("archivo.key"));
        try {
            blowfishKey = (SecretKey) oin.readObject();
        } finally {
            oin.close();
        }

        //EjemploSimetrico ej = new EjemploSimetrico(blowfishKey, blowfishKey.getAlgorithm());



        EjemploSimetrico ej = new EjemploSimetrico("k5%HiY?XxUw");

        String cadena = "Hola como estas";

        String encriptado = ej.encrypt(cadena);

        System.out.println(encriptado);

        String desencriptado = ej.decrypt(encriptado);

        System.out.println(desencriptado);
        System.out.println(cadena);
        
        


    }
}
