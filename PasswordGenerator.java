
import java.util.Arrays;
import java.util.regex.Pattern;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author JJSC
 */
public class PasswordGenerator {

    private final static String NUMEROS = "0123456789";
    private final static String MAYUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private final static String MINUSCULAS = "abcdefghijklmnopqrstuvwxyz";
    private final static String ESPECIALES = "!.,;{}^*+$%&/()=?¿¡";

    public static class ExcepcionLongitud extends Exception {

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
            if (!pass.toString().toLowerCase().contains(new String(new char[]{c}).toLowerCase())) {
                pass.append(c);
                break;
            }
        } while (true);
        return pass;
    }

    public static String getPassword(int length, String src) throws ExcepcionLongitud {
        StringBuilder pass = new StringBuilder();
        String temp;

        if (length < 8) {
            throw new ExcepcionLongitud("ERROR longitud minima es 8");
        }
        
        if (src.isEmpty()) {
            src = "mMne";
        }
        else if (src.length() == 1) {
             throw new ExcepcionLongitud("ERROR criterios deben ser al menos 2");
        } 

        boolean toogle = true;
        boolean ciclo = true;
        for (int i = 0; i < length; i++) {
            if (!ciclo) {
                break;
            }
            if (toogle) {
                if (src.contains("m") && !Pattern.compile(".+[a-z]$").matcher(pass.toString()).matches() ) {
                    makePass(pass, MINUSCULAS);
                    if (pass.toString().length() >= length) {
                        break;
                    }
                }
            } else if (src.contains("M") && !Pattern.compile(".+[A-Z]$").matcher(pass.toString()).matches() ) {
                makePass(pass, MAYUSCULAS);
                if (pass.toString().length() >= length) {
                    break;
                }
            }
            
            char[] tipos =  (toogle) ? new char[]{'n','e'} : new char[]{'e','n'};
            
            for (char t :  tipos ) {
                pass = genT(t, src, pass, length);
                if (pass.toString().length() >= length) {
                    ciclo = false;
                    break;
                }
            }
            toogle = !toogle;
        }
        return pass.toString();
    }

    private static StringBuilder genT(char type, String src, StringBuilder pass, int length) {
        if ((type == 'n') && src.contains("n") ) {
            if ( (pass.toString().length() < length) && !Pattern.compile(".+[0-9]$").matcher(pass.toString()).matches()) {
                return makePass(pass, NUMEROS);
            }
        }
        if ((type == 'e') && src.contains("e")) {
            if ( (pass.toString().length() < length) && !Pattern.compile(".+["+ESPECIALES.replaceAll("([\\\\\\.\\[\\{\\(\\*\\+\\?\\^\\$\\|])", "\\\\$1")+"]$").matcher(pass.toString()).matches()) {
                return makePass(pass, ESPECIALES);
            }
        }
        return pass;
    }

    public static void main(String[] args) throws ExcepcionLongitud {
        for (int i = 0; i < 10; i++) {
            System.out.println(getPassword(10, ""));
        }
    }
}
