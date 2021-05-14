import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
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

    public void firstStep() throws Exception{
        //FAZER LOG QUE ENTROU FASE 1
        boolean isValidated = false;
        String loginName = "";
        
        while(!isValidated){
            System.out.println("\nDigite seu login: ");
            loginName = this.scanner.next();
            
            
            isValidated = db.checkIfUserExists(loginName);

            if(!isValidated){
                //FAZER LOG QUE DEU ERRADO
                System.out.println("\nUsuario " + loginName + " nao existe.");
            }
            
            if(db.checkIfUserBlocked(loginName)){
                //FAZER LOG DE TENTATIVA DE LOGIN
                System.out.println("\nUsuario '" + loginName + "' bloqueado");
                isValidated = false; 
            }
        };
        //FAZER LOG QUE DEU CERTO
        this.login = loginName;
        this.cert = db.getDigitalCert(loginName);
        this.publicKey = cert.getPublicKey();
        this.hash = db.getPasswordHex(loginName);
        this.salt = db.getPasswordSalt(loginName);
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
                System.out.println("\nAperte [=] para 'Clear' e [-] para 'Ok'");
                Vector<String> comb = f.generateCodes(f.generateFonemas());
                for(int i = 0; i<comb.size(); i++){
                    System.out.println(Integer.toString(i + 1) + " -> " + comb.get(i));
                }  
                String keypress = this.scanner.next();
                //Reset
                if(keypress.equals("=")){
                    j = -1;
                    f.reset();
                    System.out.println("\nTeclado foi limpo");
                }
                //OK
                else if(keypress.equals("-")){
                    break;
                }
                else if(Integer.parseInt(keypress) > 0 && Integer.parseInt(keypress) < 7){
                    f.ADD(comb.get(Integer.parseInt(keypress) - 1));    
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
        System.out.println("\nLogin " + this.login + " bloqueado por numero de tentativas invalidas. Aguarde dois minutos");
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
                db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nFrase secreta invalida");
                block = db.getFailAttemptsCount(this.login);
                if(block >= 3){
                    db.blockUser(this.login);
                    firstStep();
                }   
                continue;
           } 
           catch(IOException | NullPointerException | OutOfMemoryError | SecurityException | IllegalBlockSizeException e){
                //FAZER LOG CAMINHO INVALIDO
                db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nCaminho da chave privada invalido");
                block = db.getFailAttemptsCount(this.login);
                if(block >= 3){
                    db.blockUser(this.login);
                    firstStep();
                }   
                continue;
           }
                    
            if(!isValidated){
                //FAZER LOG DA ASSINATURA DIGITAL INVALIDA
                db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nChave privada invalida, tente novamente");
                block = db.getFailAttemptsCount(this.login);
                if(block >= 3){
                    db.blockUser(this.login);
                    firstStep();
                }   
            } 
            
        }
        //FAZER LOG CHAVE PRIVADA VALIDADA
        System.out.println("\nChave validada");
        MainMenu();
    }

    public void header() throws Exception{
        System.out.println("\nLogin: " + this.login);
        System.out.println("Grupo: " + db.getUserGroup(this.login));
        System.out.println("Nome: " + db.getUserName(this.login));
    }

    public void bodyOneMainMenu() throws Exception{
        System.out.println("\nTotal de acessos do sistema: " + "2");//db.getTotalUserAccess());
    }

    public void MainMenu() throws Exception{
        String selected;
        boolean isValidOption = false;

        while(!isValidOption){
            header();
            bodyOneMainMenu();

            System.out.println("\nMenu Principal:");
            System.out.println("\n[1] - Cadastrar novo usuario");
            System.out.println("\n[2] - Alterar senha pessoal e certificado digital do usuario");
            System.out.println("\n[3] - Consultar pasta de arquivos secretos do usuario");
            System.out.println("\n[4] - Sair do Sistema");
            
            selected = this.scanner.next();
            switch(selected){
                case "1":
                    RegisterForm();
                    break;
                case "2":
                    //alterPasswordAndCertificate();
                    break;
                case "3":
                   // checkUserSecretFiles();
                    break;
                case "4":
                   // exitSystem();
                    break;
                default:
                    System.out.println("Opcao inválida");
            }        
        }        
    }

    public void bodyOneRegisterForm() throws Exception{
        System.out.println("\nTotal de usuarios do sistema: " + Integer.toString(db.getTotalUsers()));
    }

    public void RegisterForm() throws Exception{
        boolean isValidGroup;
        boolean isValidPassword;
        boolean isValidPasswordConfirmation;
        boolean isValidCertificate;
        CypherManager cm = new CypherManager();
        X509Certificate c = null;
        Fonemas f = new Fonemas();
        Vector<String> fonVector = f.generateFonemas();
        String fonema;
        String prevFonema = "-1";
        String aux;
        String certificatePath = "";
        String grupo = "";
        String password = "";
        String passwordConfirmation = "";

        while(true){
            header();
            bodyOneRegisterForm();
            isValidGroup = false;
            isValidPassword = false;
            isValidPasswordConfirmation = false;
            isValidCertificate = false;

            System.out.println("\nCaminho do certificado digital: " + certificatePath);
            while(!isValidCertificate){
                if(!(aux = scanner.next()).equals("-") && certificatePath.equals("")){
                    try{
                        c = cm.getCertificate(aux);
                        certificatePath = aux;
                        isValidCertificate = true;
                    }
                    catch(FileNotFoundException e){
                        System.out.println("\nCaminho do certificado invalido");
                        isValidCertificate = false;
                    }
                    catch(CertificateException e){
                        System.out.println("\nCertificado invalido: ");
                        isValidCertificate = false;
                    } 
                                        
                }
                else if(!certificatePath.equals("")){
                    isValidCertificate = true;
                }
            }
            System.out.println("Grupo - [1] Administrador [2] Usuario: "  + grupo );
            while(!isValidGroup){                
                switch(scanner.next()){
                    case "1":
                        grupo = "1";
                        isValidGroup = true;
                        break;
                    case "2":
                        isValidGroup = true;
                        grupo = "2";
                    case "-":
                        if(grupo.equals("1") || grupo.equals("2")){
                            isValidGroup = true;
                        }
                        break;
                    default:
                        isValidGroup = false;
                        System.out.println("\nGrupo invalido");
                }

            }
            System.out.println("\nSenha pessoal (Aperte [=] para 'Clear' e [-] para 'Ok') " + password);
            while(!isValidPassword){
                System.out.println("\nSenha : " + password);
                for(int i = 0; i < fonVector.size(); i++){
                    System.out.print(Integer.toString(i+1) + "-" + fonVector.get(i) + " ");
                }
                System.out.println();
                fonema = scanner.next();
                if(fonema.equals("-") && validadePasswordSize(password)){
                    isValidPassword = true;
                    prevFonema = "-1";
                    break;
                }
                else if(fonema.equals("-") && !validadePasswordSize(password)){
                    isValidPassword = false;
                    password = "";
                    prevFonema = "-1";
                    System.out.println("Senha invalida (precisa entre 4 e 6 fonemas)");
                    continue;
                }
                else if(fonema.equals("=")){
                    isValidPassword = false;
                    password = "";
                    prevFonema = "-1";
                    continue;
                }

                try{
                    fonema = fonVector.get(Integer.parseInt(fonema)-1);
                }catch (ArrayIndexOutOfBoundsException e){
                    System.out.println("\nOpcao invalida, escolha um dos fonemas disponiveis");
                }
                if(fonema.equals(prevFonema)){
                    isValidPassword = false;
                    System.out.println("\nSenha nao pode ter fonemas repetidos.");
                    continue;
                }
                else{
                    prevFonema = fonema;
                    password = password + fonema;

                }               
            }
            System.out.println("Digite novamente a senha para confirmar: " + passwordConfirmation);
            while(!isValidPasswordConfirmation){
                System.out.println("Senha: " + passwordConfirmation);
                for(int i = 0; i < fonVector.size(); i++){
                    System.out.print(Integer.toString(i+1) + "-" + fonVector.get(i) + " ");
                }
                System.out.println();
                fonema = scanner.next();
                if(fonema.equals("-") && password.equals(passwordConfirmation)){
                    isValidPasswordConfirmation = true;
                    prevFonema = "-1";
                    break;
                }
                else if(fonema.equals("=")){
                    isValidPasswordConfirmation = false;
                    passwordConfirmation = "";
                    prevFonema = "-1";
                    continue;
                }
                try{
                    fonema = fonVector.get(Integer.parseInt(fonema)-1);
                }catch (ArrayIndexOutOfBoundsException e){
                    System.out.println("\nOpcao invalida, escolha um dos fonemas disponiveis");
                }
                if(fonema.equals(prevFonema)){
                    isValidPassword = false;
                    System.out.println("\nSenha nao pode ter fonemas repetidos.");
                    continue;
                }
                else{
                    prevFonema = fonema;
                    passwordConfirmation = passwordConfirmation + fonema;

                }               
            }
        
        boolean failedRegistration = false;
        while(!failedRegistration){
            cm.showCertificateInformation(c);
            System.out.println("[1] - Confirmar  [2] - Voltar ao menu principal");
            
            switch(scanner.next()){
                case "1":
                    String salt = saltGenerator();
                    int g = Integer.parseInt(grupo) - 1;
                    String b64Cert = Base64.getEncoder().encodeToString(c.getEncoded());
                    try{
                        db.insertNewUser(cm.getLoginFromCertificate(c),cm.getNameFromCertificate(c),generatePEMCert(b64Cert),"SHA1", salt, generatePassword(password, salt), Integer.toString(g), "0", "0", "0");
                        RegisterForm();
                    }
                    catch(Exception e){
                        failedRegistration = true;
                        System.out.println("\nUsuario ja cadastrado.");
                    }                
                    
                    break;
                case "2":
                    MainMenu();
                    break;
                default:
                    System.out.println("Opcao invalida");
            }
        }
            

            //db.insertNewUser(login, name, cert, algorithm, salt, hexPassword, gid, accesscount, searchcount, blockcount);
        }                  
    }       
    

    public void confirmationScreen(X509Certificate c, String certPath, String grupo, String password) throws Exception{
        if(grupo.equals("1")){
            grupo = "admin";
        }
        else if(grupo.equals("2")){
            grupo="usuario";
        }

        System.out.println("\n Por favor confira os dados fornecidos:");
        System.out.println("Caminho do arquivo do certificado digital: " + certPath);
        System.out.println("Grupo: " + grupo);
        System.out.println("Senha: " + password);
        
        CypherManager cm = new CypherManager();
        cm.showCertificateInformation(c);
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

    public boolean validadePasswordSize(String password){
        int len = password.length()/2;
        if(len >=4 && len <= 6){
            return true;
        }
        return false;
    }
    //javac DigitalVault.java DatabaseManager.java CypherManager.java Fonemas.java Tree.java Node.java
    //java -cp ".;sqlite-jdbc-3.23.1.jar" DigitalVault  

    //./Pacote-T4/Keys/admin-pkcs8-des.key 
    // ca@grad.inf.puc-rio.br

    //Index file
    //XXYYZZ11 teste01.docx user01@inf1416.puc-rio.br usuario
    //XXYYZZ22 teste02.docx user02@inf1416.puc-rio.br usuario
    public static void main (String[] args){
        String adminCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
        String userCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
        String userPrivateKeyPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-pkcs8-des.key";
        String indexEnv = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.env";
        String indexEnc = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.enc";
        String indexAsd = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.asd";
        
        DigitalVault dv;
        CypherManager cp = new CypherManager();
        
        try {
            db.getConn();
            dv = new DigitalVault();
            dv.firstStep();
            //dv.header();

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
    //         db.getConn();
    //         dv.setCertificate(adminCertPath);
    //         //db.createNewTables();
    //         CypherManager cm = new CypherManager();  
    //         String salt = dv.saltGenerator();
    //         String password = dv.generatePassword("BA", salt);

    //         Key privkey = cm.getPrivateKey(userPrivateKeyPath, "user01".getBytes());
    //         String b64Cert = Base64.getEncoder().encodeToString(dv.cert.getEncoded());
            
    //          db.removeUser("ca@grad.inf.puc-rio.br");
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