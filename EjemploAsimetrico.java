
/**
 *
 * @author jjsc
 */
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher; 
import org.apache.commons.codec.binary.Base64;
import sun.security.x509.*;

public class EjemploAsimetrico {

    static void listarProveedores() {
        boolean listarProps = true;

        System.out.println("------------------------------------");
        System.out.println("Proveedores instalados en su sistema");
        System.out.println("------------------------------------");
        Provider[] listaProv = Security.getProviders();
        for (int i = 0; i < listaProv.length; i++) {
            System.out.println("Núm. proveedor : " + (i + 1));
            System.out.println("Nombre         : " + listaProv[i].getName());
            System.out.println("Versión        : " + listaProv[i].getVersion());
            System.out.println("Información    :\n  " + listaProv[i].getInfo());
            System.out.println("Propiedades    :");
            if (listarProps) {
                Enumeration propiedades = listaProv[i].propertyNames();
                while (propiedades.hasMoreElements()) {
                    String clave = (String) propiedades.nextElement();
                    String valor = listaProv[i].getProperty(clave);
                    System.out.println("  " + clave + " = " + valor);
                }
            }
            System.out.println("------------------------------------");
        }
    }

    // Generar un base64 con las fronteras
    static String convertToPem(X509Certificate cert) throws CertificateEncodingException {
        Base64 encoder = new Base64(64);
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";

        byte[] derCert = cert.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = cert_begin + pemCertPre + end_cert;
        return pemCert;
    }

    // Crear un certificado
    static X509Certificate generateCertificate(String dn, PrivateKey privkey, PublicKey publicKey, int days, String algorithm)
            throws GeneralSecurityException, IOException {


        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
        info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);

        // Update the algorith, and resign.
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);
        return cert;
    }

    private static byte[] encrypt(byte[] inpBytes, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(inpBytes);
    }

    private static byte[] decrypt(byte[] inpBytes, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(inpBytes);
    }

    public static void main(String[] unused) throws Exception {
        String algoritmo = "RSA";

        //listarProveedores();

        // Generate a key-pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algoritmo);
        kpg.initialize(2048, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        // Obtener las claves publica y privada
        PublicKey pubk = kp.getPublic();
        PrivateKey prvk = kp.getPrivate();
        // ----------------------------------------------------------

        // Convertir las llaves para guardarlas
        // Publica
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubk.getEncoded());
        String pubkKey64 = new String(Base64.encodeBase64(x509EncodedKeySpec.getEncoded()));
        // Privada
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(prvk.getEncoded());
        String prvkKey64 = new String(Base64.encodeBase64(pkcs8EncodedKeySpec.getEncoded()));
        // ----------------------------------------------------------

        // Tomar instancia del algoritomo usado
        KeyFactory keyFactory = KeyFactory.getInstance(algoritmo);

        //Leer los textos base64 y convertirlos a clave
        byte[] keyDecoded;
        // Publica
        keyDecoded = Base64.decodeBase64(pubkKey64);
        x509EncodedKeySpec = new X509EncodedKeySpec(keyDecoded);
        pubk = keyFactory.generatePublic(x509EncodedKeySpec);
        // Privada
        keyDecoded = Base64.decodeBase64(prvkKey64);
        pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyDecoded);
        prvk = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        // ----------------------------------------------------------

        System.out.println("Clave Publica \n" + pubk.toString() + "\n\nConvertida en Base64\n" + pubkKey64 + "\n");
        System.out.println("Clave Privada \n" + prvk.toString() + "\n\nConvertida en Base64\n" + prvkKey64 + "\n");

        byte[] dataBytes = "Texto a encriptar".getBytes();

        // Crear un certificado
        X509Certificate cert = generateCertificate("CN= Jorge Sainz, OU=Desarrollo, O=Independiente, C=EC ",
                prvk,
                pubk,
                360,
                "SHA1withRSA");


        //Convertir a P12
        String password = "aSdF6y";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null);
        ks.setKeyEntry("alias", (Key) prvk, password.toCharArray(), new java.security.cert.Certificate[]{cert});
        ks.store(bos, password.toCharArray());
        bos.close();
        
        // Almacenar en disco
        FileOutputStream fos = new FileOutputStream(new File("archivo.p12"));
        bos.writeTo(fos);
        bos.flush();
        bos.close();

        // Convertir a PEM Base64
        String pemString = convertToPem(cert).trim();
        // Leer el base64 y convertirlo a objeto certificado
        System.out.println("PEM a distribuir \n" + pemString + "\n");

        // Separar las fronteras del base64
        String base64 = null;

        Matcher mat = Pattern.compile("^-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----$").matcher(pemString.replaceAll("\n", "").replaceAll("\r", ""));
        if (mat.find()) {
            base64 = mat.group(1);

        }
        // Regenerar el certificado leido 
        cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(
                Base64.decodeBase64(base64)));
        System.out.println("Certificado generado a partir de un pem \n" + cert.toString() + "\n");


        cert.checkValidity();

        // ------------------------------------------------------------------------

        // Prueba de cifrar y descifrar usando las llaves publica y privada
        byte[] encBytes = encrypt(dataBytes, cert.getPublicKey());
        byte[] decBytes = decrypt(encBytes, prvk);

        boolean expected = java.util.Arrays.equals(dataBytes, decBytes);
        System.out.println("Prueba " + (expected ? "EXITOSA!" : "FALLO!"));
    }
}
