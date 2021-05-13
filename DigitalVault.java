import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.Vector;

import javax.crypto.NoSuchPaddingException;


class DigitalVault {
    private Scanner scanner;
    private Key privateKey;
    private Key publicKey;
    private Key symmetricKey;
    private X509Certificate cert;
    private String login;
    private String salt;
    private String hash;
    private static DatabaseManager db = new DatabaseManager();

    //Path to all files
    DigitalVault() throws Exception{
        this.scanner = new Scanner(System.in);
    }

    public void setCertificate(String certificatePath) throws Exception{
        CypherManager cp = new CypherManager();
        cert = cp.getCertificate(certificatePath);
        publicKey = cert.getPublicKey();
    }

    //BEGIN INTERFACE METHODS -----------------

    public void firstStep() throws Exception{
        //FAZER LOG QUE ENTROU FASE 1
        boolean isValidEmail = false;
        String login = "";

        while(!isValidEmail){
            System.out.println("Digite seu login: ");
            login = this.scanner.nextLine();
            
            
            isValidEmail = db.checkIfUserExists(login);

            if(!isValidEmail){
                //FAZER LOG QUE DEU ERRADO
                //IMPLEMENTAR METODO "checkIfUserBlocked"
                System.out.println("\nUsuario " + login + " nao existe.");
            }            
        };

        //FAZER LOG QUE DEU CERTO
        this.login = login;
        this.cert = db.getDigitalCert(login);
        this.hash = db.getPasswordHex(login);
        this.salt = db.getPasswordSalt(login);
        //FAZER LOG QUE SAIU DA FASE 1
    }

    public void secondStep() throws Exception{
        Fonemas f = new Fonemas(); 
        CypherManager cm =  new CypherManager();
        int block = db.getFailAttemptsCount(this.login);
        while(block < 3){
            System.out.println("\nEntre a opcao que contem o fonema correto:");
            for(int j = 0; j < 7; j++){
                System.out.println("Aperte 7 para Clear e 8 para Ok");
                Vector<String> comb = f.generateCodes(f.generateFonemas());
                for(int i = 0; i<comb.size(); i++){
                    System.out.println(Integer.toString(i + 1) + " -> " + comb.get(i));
                }  
                int keypress = this.scanner.nextInt();
                //Reset
                if(keypress == 7){
                    j = -1;
                    f.reset();
                }
                //OK
                else if(keypress == 8){
                    break;
                }
                else if(keypress > 0 && keypress < 7){
                    f.ADD(comb.get(keypress - 1));    
                }
                else{
                    j-=1;
                    System.out.println("Nao eh um botao valido");
                }            
            }

            Vector<String> passwordCombinations = f.combinations();
            for(String password : passwordCombinations){
                password = password.replace("-", "") + this.salt;
                MessageDigest messageDigest = MessageDigest.getInstance(db.getPasswordHashAlgorithm(this.login));
                messageDigest.update(password.getBytes("UTF8"));
                byte[] digest = messageDigest.digest();

                if(cm.byteToHex(digest).equals(db.getPasswordHex(this.login))){
                    //VALIDADO CORRETAMENTE
                    System.out.println("AUTENTICADO STEP 2");
                }
            }

            //SENHA INVALIDA
            System.out.println("Senha invalida.");
            f.reset();
            db.increaseFailAttemptsCount(this.login, block);
            block =  db.getFailAttemptsCount(this.login);
        }
        System.out.println("Login bloqueado por numero de tentativas invalidas. Aguarde dois minutos");
        firstStep();
    }
    //END INTERFACE METHODS ---------------

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

    //javac DigitalVault.java DatabaseManager.java CypherManager.java Fonemas.java Tree.java Node.java
    //java -cp ".;sqlite-jdbc-3.23.1.jar" DigitalVault  
    public static void main (String[] args){
        String adminCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/admin-x509.crt";
        String userCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
        String userPrivateKeyPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-pkcs8-des.key";
        String indexEnv = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.env";
        String indexEnc = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.enc";
        String indexAsd = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.asd";
        
        DigitalVault dv;
        
        try {
            db.getConn();
            dv = new DigitalVault();
            dv.firstStep();
            dv.secondStep();
            
            
            dv.scanner.close();
            db.closeConnection();            
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }
    // public static void main (String[] args){
    //     String adminCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/admin-x509.crt";
    //     String userCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
    //     String userPrivateKeyPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-pkcs8-des.key";
    //     String indexEnv = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.env";
    //     String indexEnc = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.enc";
    //     String indexAsd = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.asd";

    //     try {
    //         DigitalVault dv = new DigitalVault();
    //         dv.setCertificate(adminCertPath);
    //         dv.setDatabase("test.db");
    //         DatabaseManager db = new DatabaseManager(dv.pathToDB);
    //         //db.createNewTables();
    //         CypherManager cm = new CypherManager();  
    //         String salt = dv.saltGenerator();
    //         String password = dv.generatePassword("FADAHADEBA", salt);

    //         Key privkey = cm.getPrivateKey(userPrivateKeyPath, "user01".getBytes());
    //         String b64Cert = Base64.getEncoder().encodeToString(dv.cert.getEncoded());
            
    //          db.removeUser("teste123@gmail.com");
    //          db.insertNewUser("ca@grad.inf.puc-rio.br", "AC INF1416", dv.generatePEMCert(b64Cert), "SHA-1", salt, password, "0", "0", "0", "0");
            
    //     //    // ByteArrayInputStream certBytes = new ByteArrayInputStream(decoded);
    //     //     X509Certificate ce = db.getDigitalCert("teste123@gmail.com");
    //     //     System.out.println(ce.getSubjectX500Principal());


    //     //     Key key = cm.getSymmetricKey(indexEnv, privkey);
    //     //     String index= new String(cm.decryptFile(Files.readAllBytes(new File(indexEnc).toPath()), key));

    //     //     System.out.println(index);

    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }
    // }
}