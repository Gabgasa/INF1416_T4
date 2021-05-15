import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class CypherManager {

    CypherManager(){ 
    }

    public X509Certificate getCertificate(String pathToCertificate) throws Exception{
        X509Certificate cert = null;

        FileInputStream fis = new FileInputStream(pathToCertificate);
        BufferedInputStream bis = new BufferedInputStream(fis);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while(bis.available() > 0){
            cert = (X509Certificate) cf.generateCertificate(bis);
        }

        return cert;
    }

    public Key getSymmetricKey(String pathToDigitalEnv, Key privateKey) throws Exception{
        byte[] env;
        File digitalEnv = new File(pathToDigitalEnv);
        Key symmetricalKey = null;
        
        env = Files.readAllBytes(digitalEnv.toPath());

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] seed = cipher.doFinal(env);
        SecureRandom sc = SecureRandom.getInstance("SHA1PRNG");
        sc.setSeed(seed);
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56, sc);
        symmetricalKey = keyGen.generateKey();

        return symmetricalKey;

    }

    public Key getPrivateKey(String pathToPrivateKey, byte[] secretPhrase) throws Exception{
        Key privateKey = null;
        File pkFile = new File(pathToPrivateKey);
        byte[] encoded;
        String pk64 = null;
        
        byte[] pkDES = Files.readAllBytes(pkFile.toPath());

        
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecureRandom sc = SecureRandom.getInstance("SHA1PRNG");
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        sc.setSeed(secretPhrase);            
        keyGen.init(56, sc);
        Key key = keyGen.generateKey();
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        //pk64 = cipher.doFinal(pkDES).toString();//private key in base64
        encoded = cipher.doFinal(pkDES);//private key in base64
        pk64 = new String(encoded, StandardCharsets.UTF_8);
        String pkPEM = pk64
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll("\n", "")
            .replace("-----END PRIVATE KEY-----", "");

        encoded = Base64.getDecoder().decode(pkPEM);

        PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKey = kf.generatePrivate(keyspec);
                                
        return privateKey;
    }

    public byte[] decryptFile(byte[] file, Key key) throws Exception{
        byte[] res;
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        res = cipher.doFinal(file);

        return res;
    }


    public Boolean validateFile(byte[] file, byte[] signature, Key key) throws Exception{
                //
            // verifica a assinatura com a chave publica
            //System.out.println( "\nStart signature verification" );
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initVerify((PublicKey)key);
            sig.update(file);
            try {
                if (sig.verify(signature)) {
                    return true;
                } else {
                    return false;
                }
            } catch (SignatureException se) {
            System.out.println( "Singature failed" );
            return false;
            }
        

    }

    public String byteToHex(byte[] data){
        // converte o digist para hexadecimal
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < data.length; i++) {
            String hex = Integer.toHexString(0x0100 + (data[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }

        return buf.toString();
    }
    
    
    public byte[] getDecryptedFile(String pathToFileEnv, String pathToFileEnc, Key privKey) throws Exception{
        String file = "";
        Key symmetricalKey = this.getSymmetricKey(pathToFileEnv, privKey);
        
        File ind = new File(pathToFileEnc);
        byte[] encryptedFile = Files.readAllBytes(ind.toPath());
        byte[] fileBytes = this.decryptFile(encryptedFile, symmetricalKey);

        //System.out.println(new String(index, StandardCharsets.UTF_8));

        file = new String(fileBytes, StandardCharsets.UTF_8);

        return fileBytes;
    }
    public String getNameFromCertificate(X509Certificate c) throws Exception{
        String name;
        name = c.getSubjectX500Principal().toString();
        name = name.split(",")[1];
        name = name.split("=")[1];
        return name;
    }

    public String getLoginFromCertificate(X509Certificate c) throws Exception{
        String loginName;
        loginName = c.getSubjectX500Principal().toString();
        loginName = loginName.split(",")[0];
        loginName = loginName.split("=")[1];
        return loginName;
    }

    public void showCertificateInformation(X509Certificate c) throws Exception{
        System.out.println("\nCertificado Digital");
        System.out.println("\nVersao: " + Integer.toString(c.getVersion()));
        System.out.println("Serie: " + c.getSerialNumber().toString(16));
        System.out.println("Validade: " + c.getNotAfter());
        System.out.println("Tipo de assinatura: " + c.getSigAlgName());
        System.out.println("Emissor: " + c.getIssuerDN().toString().split(",")[1]);
        System.out.println("Sujeito: " + getNameFromCertificate(c));
        System.out.println("E-mail: " + getLoginFromCertificate(c));
    }

  
}

