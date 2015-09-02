/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author JAVA
 */
public class PasswordGenerator {

    private final static String NUMEROS = "0123456789";
    private final static String MAYUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private final static String MINUSCULAS = "abcdefghijklmnopqrstuvwxyz";
    private final static String ESPECIALES = "!.,;{}^*+$%&/()=?¿¡";

    private static class ExcepcionLongitud extends Exception {
        public ExcepcionLongitud(String msg) {
            super(msg);
        }
    }

    private static char getRandomChar(String key) {
        return (key.charAt((int) (Math.random() * key.length())));
    }

    private static StringBuilder makePass(StringBuilder pass, String src) {
        char c;
        do {
            c = getRandomChar(src);
            if (!pass.toString().contains(new String(new char[]{c}))) {
                pass.append(c);
                break;
            }
        } while (true);
        return pass;
    }

    public static String getPassword(int length) throws ExcepcionLongitud {
        StringBuilder pass = new StringBuilder();

        if (length < 8) {
            throw new ExcepcionLongitud("ERROR longitud minima es 8");
        }

        for (int i = 0; i < length; i++) {
            pass = makePass(pass, MINUSCULAS);
            if (pass.toString().length() >= length) {
                break;
            }
            pass = makePass(pass, NUMEROS);
            if (pass.toString().length() >= length) {
                break;
            }
            pass = makePass(pass, MAYUSCULAS);
            if (pass.toString().length() >= length) {
                break;
            }
            pass = makePass(pass, ESPECIALES);
            if (pass.toString().length() >= length) {
                break;
            }
            
        }
        return pass.toString();
    }

    public static void main(String[] args) throws ExcepcionLongitud {
        for (int i = 0; i < 5; i++) {
            System.out.println(getPassword(10));
        }
    }
}
