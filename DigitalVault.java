import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;

import javax.crypto.NoSuchPaddingException;


class DigitalVault {
    private Key privateKey;
    private Key publicKey;
    private Key symmetricKey;
    private X509Certificate cert;
    private String pathToDB;

    //Path to all files
    DigitalVault(String certificatePath, String database) throws Exception{
        CypherManager cp = new CypherManager();
        cert = cp.getCertificate(certificatePath);
        publicKey = cert.getPublicKey();
        this.pathToDB = database;
    }

    public void loadPrivateKey(String secretPhrase, String privKeyPath) throws Exception{
        CypherManager cp = new CypherManager();
        privateKey = cp.getPrivateKey(privKeyPath, secretPhrase.getBytes());
    }

    public String generatePassword(String senha, String salt) throws Exception{
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        CypherManager cp = new CypherManager();
        
        messageDigest.update((senha+salt).getBytes("UTF8"));
        byte [] digest = messageDigest.digest();

        String hexPassword = cp.byteToHex(digest);
        return hexPassword;
    }

    public String saltGenerator() {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        String salt = "";
        Random rand = new Random();
        int upperbound = alphabet.length();
        for (int i = 0; i < 10; i++) {
            int int_random = rand.nextInt(upperbound);

            salt += alphabet.substring(int_random, int_random + 1);
        }
        return salt;
    }

    public String generatePEMCert(String certificate){
        String certPEM = "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----";
        return certPEM;
    }


    //javac DigitalVault.java DatabaseManager.java CypherManager.java
    //java -cp ".;sqlite-jdbc-3.23.1.jar" DigitalVault  
    public static void main (String[] args){
        
        String userCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
        String userPrivateKeyPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-pkcs8-des.key";
        String indexEnv = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.env";
        String indexEnc = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.enc";
        String indexAsd = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.asd";

        try {
            DigitalVault dv = new DigitalVault(userCertPath, "test.db");

            DatabaseManager db = new DatabaseManager(dv.pathToDB);
            CypherManager cm = new CypherManager();  
            String salt = dv.saltGenerator();
            String password = dv.generatePassword("senha123", salt);

            Key privkey = cm.getPrivateKey(userPrivateKeyPath, "user01".getBytes());
            String b64Cert = Base64.getEncoder().encodeToString(dv.cert.getEncoded());
            
            db.removeUser("teste123@gmail.com");
            db.insertNewUser("teste123@gmail.com", "Gabriel Aquino", dv.generatePEMCert(b64Cert), "SHA-1", salt, password);
            
           // ByteArrayInputStream certBytes = new ByteArrayInputStream(decoded);
            X509Certificate ce = db.getDigitalCert("teste123@gmail.com");
            System.out.println(ce.getSubjectX500Principal());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}