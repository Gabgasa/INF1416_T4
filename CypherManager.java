import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.EncodedKeySpec;
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
        String pk64 = null;
        
        byte[] pkDES = Files.readAllBytes(pkFile.toPath());

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        try {
            SecureRandom sc = SecureRandom.getInstance("SHA1PRNG");
            sc.setSeed(secretPhrase);
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(sc);
            keyGen.init(56);
            cipher.init(Cipher.DECRYPT_MODE, keyGen.generateKey());
            pk64 = cipher.doFinal(pkDES);//private key in base64

            String pkPEM = pk64
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(Systen.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

            pkBytes = Base64.decodeBase64(pkPEM);

            PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(pkBytes);
            KeyFactory kf = new KeyFactory();
            privateKey = kf.generatePrivate(keyspec);
                                    
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return privateKey;

    }
}
