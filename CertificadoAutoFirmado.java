

import com.google.common.base.Strings;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;


/**
 * http://www.bouncycastle.org/ Bouncy Castle library.
 *
 */
public class CertificadoAutoFirmado {

    static {
       Security.addProvider(new BouncyCastleProvider());
    }

   
    @SuppressWarnings("deprecation")
    static void generateSelfSignedX509Certificate() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException,
            SignatureException, InvalidKeyException, IOException {

        Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        // para 2 años
        Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

        // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // X509 CERTIFICATE
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=Jorge Sainz, OU=Independiente, C=EC");

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName); 
        certGen.setNotBefore(validityBeginDate);
        certGen.setNotAfter(validityEndDate);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");

        // Impresion de resultados
        System.out.println(Strings.repeat("=", 80));
        System.out.println("CERTIFICATE TO_STRING");
        System.out.println(Strings.repeat("=", 80));
        System.out.println();
        System.out.println(cert);
        System.out.println();

        System.out.println(Strings.repeat("=", 80));
        System.out.println("CERTIFICATE PEM ");
        System.out.println(Strings.repeat("=", 80));
        System.out.println();
        PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
        pemWriter.writeObject(cert);
        pemWriter.flush();
        System.out.println();

        System.out.println(Strings.repeat("=", 80));
        System.out.println("PRIVATE KEY PEM ");
        System.out.println(Strings.repeat("=", 80));
        System.out.println();
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.flush();
        System.out.println();
    }

    public static void main(String[] args) {
        try {
            generateSelfSignedX509Certificate();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
