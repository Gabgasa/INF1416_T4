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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
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
        boolean isValidated = false;
        String login = "";
        
        while(!isValidated){
            System.out.println("\nDigite seu login: ");
            login = this.scanner.next();
            
            
            isValidated = db.checkIfUserExists(login);

            if(!isValidated){
                //FAZER LOG QUE DEU ERRADO
                System.out.println("\nUsuario " + login + " nao existe.");
            }
            
            if(db.checkIfUserBlocked(this.login)){
                //FAZER LOG DE TENTATIVA DE LOGIN
                System.out.println("\nUsuario '" + this.login + "' bloqueado");
                isValidated = false; 
            }
        };

        //FAZER LOG QUE DEU CERTO
        this.login = login;
        this.cert = db.getDigitalCert(login);
        this.publicKey = cert.getPublicKey();
        this.hash = db.getPasswordHex(login);
        this.salt = db.getPasswordSalt(login);
        secondStep();
        //FAZER LOG QUE SAIU DA FASE 1
    }

    public void secondStep() throws Exception{
        Fonemas f = new Fonemas(); 
        CypherManager cm =  new CypherManager();
        int block = db.getFailAttemptsCount(this.login);
        String passwordHex = db.getPasswordHex(this.login);
        String hashAlgorithm = db.getPasswordHashAlgorithm(this.login);

        while(!db.checkIfUserBlocked(this.login)){
            System.out.println("\nEntre a opcao que contem o fonema correto:");
            for(int j = 0; j < 7; j++){
                System.out.println("\nAperte [7] para 'Clear' e [8] para 'Ok'");
                Vector<String> comb = f.generateCodes(f.generateFonemas());
                for(int i = 0; i<comb.size(); i++){
                    System.out.println(Integer.toString(i + 1) + " -> " + comb.get(i));
                }  
                int keypress = this.scanner.nextInt();
                //Reset
                if(keypress == 7){
                    j = -1;
                    f.reset();
                    System.out.println("\nTeclado foi limpo");
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
                    System.out.println("\nNao eh um botao valido");
                }
                System.out.println("\nSenha:");
                for(int k = 0; k <= j; k++){
                    System.out.print("## ");
                }  
                System.out.println();          
            }
            Vector<String> passwordCombinations = f.combinations();
            for(String password : passwordCombinations){
                password = password.replace("-", "") + this.salt;
                MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
                messageDigest.update(password.getBytes("UTF8"));
                byte[] digest = messageDigest.digest();

                if(cm.byteToHex(digest).equals(passwordHex)){
                    //FAZER LOG VALIDADO CORRETAMENTE
                    System.out.println("\nAUTENTICADO STEP 2");
                    thirdStep();
                    db.increaseFailAttemptsCount(this.login, -1); //Resetando o contador de erros
                    return;
                }
            }

            //FAZER LOG SENHA INVALIDA
            System.out.println("\nSenha invalida.");
            f.reset();
            db.increaseFailAttemptsCount(this.login, block);
            block =  db.getFailAttemptsCount(this.login);
            if(block >= 3){
                //FAZER LOG DE BLOQUEIO USUARIO
                db.blockUser(this.login);
            }
        }
        System.out.println("\nLogin " + this.login + " por numero de tentativas invalidas. Aguarde dois minutos");
        firstStep();
    }

    public void thirdStep() throws Exception{
        String secretPhrase;
        String privateKeyPath;
        Key privKey;
        boolean isValidated = false;
        int block = db.getFailAttemptsCount(this.login);
        CypherManager cm = new CypherManager();

        byte[] randomByteArray = new byte[2048];
        SecureRandom.getInstanceStrong().nextBytes(randomByteArray); //Gera um array aleatorio de 2048 bytes que sera assinado com a Private Key

        while(!isValidated){
            System.out.println("\nAnexe sua chave privada.");
            privateKeyPath = this.scanner.next();
            System.out.println("\nDigite sua frase secreta.");
            secretPhrase = this.scanner.next();

            //Recovering private key
           try{
            privKey = cm.getPrivateKey(privateKeyPath, secretPhrase.getBytes());
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initSign((PrivateKey)privKey);
            sig.update(randomByteArray);
            byte[] signature = sig.sign();
            isValidated = cm.validateFile(randomByteArray, signature, this.publicKey);
            this.privateKey = privKey;
           } 
           catch(BadPaddingException e){
                //FAZER LOG FRASE SECRETA INVALIDA
                //db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nFrase secreta invalida");
                continue;
           } 
           catch(IOException | NullPointerException | OutOfMemoryError | SecurityException | IllegalBlockSizeException e){
                //FAZER LOG CAMINHO INVALIDO
                //db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nCaminho da chave privada invalido");
                continue;
           }
                    
            if(!isValidated){
                //FAZER LOG DA ASSINATURA DIGITAL INVALIDA
                //db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nChave privada invalida, tente novamente");
            } 
            block = db.getFailAttemptsCount(this.login);   
        }
        //FAZER LOG CHAVE PRIVADA VALIDADA
        System.out.println("\nChave validada");
        return;
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

    //C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/admin-pkcs8-des.key
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