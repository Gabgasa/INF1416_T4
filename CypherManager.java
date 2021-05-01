import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

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

    public Key getPrivateKey(byte[] secretPhrase) throws IOException{
        Key privateKey = null;
        File pkFile = new File(pathToPrivateKey);
        byte[] pkBytes;
        String pk64 = null;
        
        byte[] pkDES = Files.readAllBytes(pkFile.toPath());

        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecureRandom sc = SecureRandom.getInstance("SHA1PRNG");
            sc.setSeed(secretPhrase);
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(sc);
            keyGen.init(56);
            cipher.init(Cipher.DECRYPT_MODE, keyGen.generateKey());
            pk64 = cipher.doFinal(pkDES).toString();//private key in base64

            String pkPEM = pk64
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

            pkBytes = Base64.getDecoder().decode(pkPEM);

            PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(pkBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(keyspec);
                                    
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }

        return privateKey;

    }
}
