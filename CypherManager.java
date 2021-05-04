import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
            keyGen.init(56, sc);
            symmetricalKey = keyGen.generateKey();
            
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        
        return symmetricalKey;

    }

    public Key getPrivateKey(byte[] secretPhrase) throws IOException{
        Key privateKey = null;
        File pkFile = new File(pathToPrivateKey);
        byte[] encoded;
        String pk64 = null;
        
        byte[] pkDES = Files.readAllBytes(pkFile.toPath());

        try {
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
                    System.out.println( "Signature verified" );
                    return true;
                } else {
                    System.out.println( "Signature failed" ); 
                    return false;
                }
            } catch (SignatureException se) {
            System.out.println( "Singature failed" );
            return false;
            }
        

    }

    private String byteToHex(byte[] data){
        // converte o digist para hexadecimal
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < data.length; i++) {
            String hex = Integer.toHexString(0x0100 + (data[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }

        return buf.toString();
    }  

    //test
    public static void main (String[] args){
        
        String userCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
        String userPrivateKeyPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-pkcs8-des.key";
        String indexEnv = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.env";
        String indexEnc = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.enc";
        String indexAsd = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.asd";

        CypherManager cp = new CypherManager(userCertPath, userPrivateKeyPath);

        try {
            Key publickey = cp.getPublicKey();
            //System.out.println(publickey);

            Key privateKey = cp.getPrivateKey("user01".getBytes("UTF8"));
            //System.out.println(privateKey);

            Key symmetricalKey = cp.getSymmetricKey(indexEnv, privateKey);
            //System.out.println(symmetricalKey);
            File ind = new File(indexEnc);
            byte[] indFile = Files.readAllBytes(ind.toPath());
            byte[] index = cp.decryptFile(indFile, symmetricalKey);

            //System.out.println(new String(index, StandardCharsets.UTF_8));
            File indexSig = new File(indexAsd);
            byte[] sig = Files.readAllBytes(indexSig.toPath());

            cp.validateFile(index, sig, publickey);
            
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
