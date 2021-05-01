import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.security.cert.Certificate;

public class CypherManager {
    String pathToCertificate, pathToPrivateKey;

    CypherManager(String pathToCertificate, String pathToPrivateKey){
        this.pathToCertificate = pathToCertificate;
        this.pathToPrivateKey = pathToPrivateKey;        
    }

    public Key getPublicKey() throws CertificateException, IOException{
        Certificate cert = null;

        FileInputStream fis = new FileInputStream(pathToCertificate);
        BufferedInputStream bis = new BufferedInputStream(fis);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while(bis.available() > 0){
            cert = cf.generateCertificate(bis);
        }

        return cert.getPublicKey();
    }

    public Key getSymmetricKey(String pathToDigitalEnv, Key privateKey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException{
        byte[] env;
        File digitalEnv = new File(pathToDigitalEnv);
        Key symmetricalKey = null;
        
        env = Files.readAllBytes(digitalEnv.toPath());

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] seed = cipher.doFinal(env);
            SecureRandom sc = SecureRandom.getInstance("SHA1PRNG");
            sc.setSeed(seed);
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(sc);
            keyGen.init(56);
            symmetricalKey = keyGen.generateKey();
            
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        
        return symmetricalKey;

    }
}
