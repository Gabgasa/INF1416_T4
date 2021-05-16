
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.Vector;
import java.io.FileOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;


class DigitalVault {
    private Scanner scanner;
    private Key privateKey;
    private Key publicKey;
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
        boolean isValidated = false;
        String loginName = "";
        db.addLog(1001);
        db.addLog(2001);
        while(!isValidated){
            System.out.println("\nDigite seu login: ");
            loginName = this.scanner.next();
            
            
            isValidated = db.checkIfUserExists(loginName);

            if(!isValidated){
                System.out.println("\nUsuario " + loginName + " nao existe.");
                db.addLog(2005, loginName); //Usuario n existe
            }
            
            if(db.checkIfUserBlocked(loginName)){
                db.addLog(2004, loginName); //acesso bloqueado
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
        db.addLog(2003, loginName); //acesso liberado
        db.addLog(2002); //autenticacao etapa 1 encerrada
        secondStep();
        //FAZER LOG QUE SAIU DA FASE 1
    }

    public void secondStep() throws Exception{
        Fonemas f = new Fonemas(); 
        CypherManager cm =  new CypherManager();
        int block = db.getFailAttemptsCount(this.login);
        String passwordHex = db.getPasswordHex(this.login);
        String hashAlgorithm = db.getPasswordHashAlgorithm(this.login);
        int keypressnumber = 0;

        db.addLog(3001, this.login); //Etapa 2 iniciada
        while(!db.checkIfUserBlocked(this.login)){
            System.out.println("\nEntre a opcao que contem o fonema correto:");
            for(int j = 0; j < 7; j++){
                System.out.println("\nAperte [=] para 'Clear' e [-] para 'Ok'");
                Vector<String> comb = f.generateCodes(f.generateFonemas());
                for(int i = 0; i<comb.size(); i++){
                    System.out.println(Integer.toString(i + 1) + " -> " + comb.get(i));
                }  
                String keypress = this.scanner.next();
                if(keypress.equals("-")){
                    break;
                }
                
                //Resetd
                if(keypress.equals("=")){
                    j = -1;
                    f.reset();
                    System.out.println("\nTeclado foi limpo");
                    continue;
                }
                try{
                    keypressnumber = Integer.parseInt(keypress);
                    if(keypressnumber > 0 && keypressnumber < 7){                    
                        f.ADD(comb.get(Integer.parseInt(keypress) - 1));                      
                    }
                    else{
                        j-=1;
                        System.out.println("\nNao eh um botao valido");
                    }
                }
                catch(Exception e){
                    System.out.println("\nOpcao invalida");
                    continue;
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
                    db.addLog(3003, this.login);
                    db.increaseFailAttemptsCount(this.login, -1); //Resetando o contador de erros
                    db.addLog(3002, this.login);
                    thirdStep();                    
                }
            }

            //FAZER LOG SENHA INVALIDA
            System.out.println("\nSenha invalida.");
            f.reset();
            db.increaseFailAttemptsCount(this.login, block);
            block =  db.getFailAttemptsCount(this.login);
            if(block >= 3){
                System.out.println("\nLogin " + this.login + " bloqueado por numero de tentativas invalidas. Aguarde dois minutos");
                db.addLog(3006, this.login);
                db.addLog(3007, this.login);
                db.increaseFailAttemptsCount(this.login, -1); //Resetando o contador de erros
                db.blockUser(this.login);
            }
            else if(block == 1){
                db.addLog(3004, this.login);
            }
            else if(block == 2){
                db.addLog(3005, this.login);
            }
        }
        
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
        db.addLog(4001, this.login);

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
                db.addLog(4005, this.login);
                block = db.getFailAttemptsCount(this.login);
                if(block >= 3){
                    System.out.println("\nLogin " + this.login + " bloqueado por numero de tentativas invalidas. Aguarde dois minutos");
                    db.blockUser(this.login);
                    db.increaseFailAttemptsCount(this.login, -1); //Resetando o contador de erros
                    db.addLog(4007, this.login);
                    firstStep();
                }   
                continue;
           } 
           catch(IOException | NullPointerException | OutOfMemoryError | SecurityException | IllegalBlockSizeException e){
                //FAZER LOG CAMINHO INVALIDO
                db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nCaminho da chave privada invalido");
                db.addLog(4004, this.login);
                block = db.getFailAttemptsCount(this.login);
                if(block >= 3){
                    System.out.println("\nLogin " + this.login + " bloqueado por numero de tentativas invalidas. Aguarde dois minutos");
                    db.blockUser(this.login);
                    db.increaseFailAttemptsCount(this.login, -1); //Resetando o contador de erros
                    db.addLog(4007, this.login);
                    firstStep();
                }   
                continue;
           }
                    
            if(!isValidated){
                //FAZER LOG DA ASSINATURA DIGITAL INVALIDA
                db.increaseFailAttemptsCount(this.login, block);
                System.out.println("\nChave privada invalida, tente novamente");
                db.addLog(4006, this.login);
                block = db.getFailAttemptsCount(this.login);
                if(block >= 3){
                    System.out.println("\nLogin " + this.login + " bloqueado por numero de tentativas invalidas. Aguarde dois minutos");
                    db.addLog(4007, this.login);
                    db.increaseFailAttemptsCount(this.login, -1); //Resetando o contador de erros
                    db.blockUser(this.login);
                    firstStep();
                }   
            } 
            
        }
        //FAZER LOG CHAVE PRIVADA VALIDADA
        System.out.println("\nChave validada");
        db.addUserTotalAccess(this.login);
        db.addLog(4003, this.login);
        db.addLog(4002, this.login);
        MainMenu();
    }

    public void header() throws Exception{
        System.out.println("\nLogin: " + this.login);
        System.out.println("Grupo: " + db.getUserGroup(this.login));
        System.out.println("Nome: " + db.getUserName(this.login));
    }

    public void bodyOneMainMenu() throws Exception{
        System.out.println("\nTotal de acessos do sistema: " + db.getUserTotalAccess(login));
    }

    public void MainMenu() throws Exception{
        String selected;
        boolean isValidOption = false;
        db.addLog(5001, this.login);
        while(!isValidOption){
            header();
            bodyOneMainMenu();

            if(db.getUserGroup(this.login).equals("admin")){
                System.out.println("\nMenu Principal:");
                System.out.println("\n[1] - Cadastrar novo usuario");
                System.out.println("\n[2] - Alterar senha pessoal e certificado digital do usuario");
                System.out.println("\n[3] - Consultar pasta de arquivos secretos do usuario");
                System.out.println("\n[4] - Sair do Sistema");
                
                selected = this.scanner.next();
                switch(selected){
                    case "1":
                        db.addLog(5002, this.login);
                        RegisterForm();
                        break;
                    case "2":
                        db.addLog(5003, this.login);
                        changePasswordAndCertificateMenu(); 
                        break;
                    case "3":
                        db.addLog(5004, this.login);
                        checkUserSecretFolder();
                        break;
                    case "4":
                        db.addLog(5005, this.login);
                        exitSystemMenu();
                        break;
                    default:
                        System.out.println("Opcao inválida");
                }        
            }
            else{
                System.out.println("\nMenu Principal:");
                System.out.println("\n[1] - Alterar senha pessoal e certificado digital do usuario");
                System.out.println("\n[2] - Consultar pasta de arquivos secretos do usuario");
                System.out.println("\n[3] - Sair do Sistema");
                
                selected = this.scanner.next();
                switch(selected){
                    case "1":
                        db.addLog(5002, this.login);
                        changePasswordAndCertificateMenu(); 
                        break;
                    case "2":
                        db.addLog(5003, this.login);
                        checkUserSecretFolder();
                        break;
                    case "3":
                        db.addLog(5004, this.login);
                        exitSystemMenu();
                        break;
                    default:
                        System.out.println("Opcao invalida");
                }
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
        db.addLog(6001, this.login);

        while(true){
            header();
            bodyOneRegisterForm();
            isValidGroup = false;
            isValidPassword = false;
            isValidPasswordConfirmation = false;
            isValidCertificate = false;

            System.out.println("\nAperte [1] para cadastrar e [2] para voltar ao menu principal");
            switch(this.scanner.next()){
                case "1":
                    break;
                case "2":
                    db.addLog(6007, this.login);
                    MainMenu();
            }

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
                        db.addLog(6004, this.login);
                        isValidCertificate = false;
                    }
                    catch(CertificateException e){
                        System.out.println("\nCertificado invalido: ");
                        db.addLog(6004, this.login);
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
                    db.addLog(6003, this.login);
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
                }
                catch(Exception e){
                    System.out.println("\nOpcao invalida, escolha um dos fonemas disponiveis");
                    continue;
                }
                if(fonema.equals(prevFonema)){
                    isValidPassword = false;
                    db.addLog(6003, this.login);
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
                }
                catch (Exception e){
                    System.out.println("\nOpcao invalida, escolha um dos fonemas disponiveis");
                    continue;
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
            System.out.println("[1] - Confirmar  [2] Rejeitar  [3] - Voltar ao menu principal");
            
            switch(scanner.next()){
                case "1":
                    db.addLog(6005, this.login);
                    db.addLog(6002, this.login);
                    String salt = saltGenerator();
                    int g = Integer.parseInt(grupo) - 1;
                    
                    String b64Cert = Base64.getEncoder().encodeToString(c.getEncoded());
                    try{
                        db.insertNewUser(cm.getLoginFromCertificate(c),cm.getNameFromCertificate(c),generatePEMCert(b64Cert),"SHA-1", salt, generatePassword(password, salt), Integer.toString(g), "0", "0", "0");
                        System.out.println("\nUsuario " + cm.getLoginFromCertificate(c) + " cadastrado com sucesso.");
                        MainMenu();
                    }
                    catch(Exception e){
                        failedRegistration = true;
                        System.out.println("\nUsuario ja cadastrado.");
                    }                
                    
                    break;
                case "2":
                    db.addLog(6006, this.login);
                    RegisterForm();
                    break;
                case "3":
                    db.addLog(6007, this.login);
                    MainMenu();
                    break;
                default:
                    System.out.println("Opcao invalida");
            }
        }
            
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

    public void changePasswordAndCertificateMenu() throws Exception{
        boolean isValidCertificate = false;
        boolean isValidPassword = false;
        boolean isValidPasswordConfirmation = false;
        Fonemas f = new Fonemas();
        Vector<String> fonVector = f.generateFonemas();
        String prevFonema = "-1";
        String fonema = "";
        String aux = "";
        String certificatePath = "";
        X509Certificate c = null;
        String password = "";
        String passwordConfirmation = "";
        boolean changingPassword = true;
        boolean changingCert = true;

        CypherManager cm = new CypherManager();
        db.addLog(7001, this.login);
        while(true){
            header();
            bodyOneMainMenu();

            System.out.println("\nAperte [1] para Continuar com mudanca e [2] para voltar ao menu principal");
            switch(this.scanner.next()){
                case "1":
                    break;
                case "2":
                    db.addLog(7006, this.login);
                    MainMenu();
            }           

            System.out.println("\nDigite o caminho do novo Certificado ou aperte [-] para mante-lo.");
            while(!isValidCertificate){
                if(!(aux = scanner.next()).equals("-") && certificatePath.equals("")){
                    try{
                        c = cm.getCertificate(aux);
                        certificatePath = aux;
                        isValidCertificate = true;
                    }
                    catch(FileNotFoundException e){
                        System.out.println("\nCaminho do certificado invalido");
                        db.addLog(7003, this.login);
                        isValidCertificate = false;
                    }
                    catch(CertificateException e){
                        System.out.println("\nCertificado invalido: ");
                        db.addLog(7003, this.login);
                        isValidCertificate = false;
                    } 
                                        
                }
                else if(certificatePath.equals("")){
                    //Sem mudanca realizada
                    changingCert = false;
                    isValidCertificate = true;
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
                if(fonema.equals("-") && password.equals("")){
                    //Não está trocando a senha
                    isValidPassword = true;
                    isValidPasswordConfirmation = true;
                    changingPassword = false;
                    break;
                }
                else if(fonema.equals("-") && validadePasswordSize(password)){
                    isValidPassword = true;
                    prevFonema = "-1";
                    break;
                }
                else if(fonema.equals("-") && !validadePasswordSize(password)){
                    isValidPassword = false;
                    db.addLog(7002, this.login);
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
                }catch (Exception e){
                    System.out.println("\nOpcao invalida, escolha um dos fonemas disponiveis");
                    continue;
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
            while(!isValidPasswordConfirmation){
                System.out.println("Digite novamente a senha para confirmar: " + passwordConfirmation);
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
                else if(fonema.equals("-") && !password.equals(passwordConfirmation)){
                    passwordConfirmation = "";
                    prevFonema = "-1";
                    isValidPasswordConfirmation = false;
                    System.out.println("\nConfirmacao invalida, digite novamente");
                    continue;
                }
                else if(fonema.equals("=")){
                    isValidPasswordConfirmation = false;
                    passwordConfirmation = "";
                    prevFonema = "-1";
                    continue;
                }
        
                if(fonema.equals(prevFonema)){
                    isValidPassword = false;
                    System.out.println("\nSenha nao pode ter fonemas repetidos.");
                    continue;
                }
                else{
                    try{
                        fonema = fonVector.get(Integer.parseInt(fonema)-1);
                    }catch (Exception e){
                        System.out.println("\nOpcao invalida, escolha um dos fonemas disponiveis");
                        continue;
                    }
                    prevFonema = fonema;
                    passwordConfirmation = passwordConfirmation + fonema;

                }               
            }
        
        while(true){
            if(c != null){
                cm.showCertificateInformation(c);
            }
            else{
                c = db.getDigitalCert(this.login);
                cm.showCertificateInformation(c);
            }
            
            System.out.println("[1] - Confirmar  [2] Rejeitar e voltar ao menu inicial");
            
            switch(scanner.next()){
                case "1":
                    db.addLog(7004, this.login);

                    if(changingPassword){
                        String salt = saltGenerator();
                        String newPassword = generatePassword(password, salt);
                        db.changeUserPassword(this.login, salt, newPassword);       
                    }   
                    
                    if(changingCert){
                        String b64Cert = Base64.getEncoder().encodeToString(c.getEncoded());
                        String pemCert = generatePEMCert(b64Cert);                                
                        db.changeUserCertificate(login, pemCert);
                    }                    
                    MainMenu();         
                    break;
                case "2":
                    db.addLog(7005, this.login);
                    db.addLog(7006, this.login);
                    MainMenu();
                    break;
                default:
                    System.out.println("Opcao invalida");
            }
        }
        }
    }

    public void checkUserSecretFolder() throws Exception{
        CypherManager cm = new CypherManager();
        boolean isValid = false;
        db.addLog(8001, this.login);
        while(true){
            header();
            System.out.println("\nTotal de consultas do usuario: " + db.getTotalSearchCount(this.login));

            System.out.println("[1] - Listar arquivos [2] - Voltar ao menu principal");
            while(!isValid){
                switch(this.scanner.next()){
                    case "1":
                        db.addLog(8003, this.login);
                        isValid = true;
                        break;
                    case "2":
                        db.addLog(8002, this.login);
                        MainMenu();
                    default:
                        System.out.println("\nOpcao invalida");
                }                

            }
            isValid = false;
            System.out.println("\nDigite o caminho da pasta:");
            String folderPath = this.scanner.next();
            String indexEnv = folderPath + "/index.env";
            String indexAsd = folderPath + "/index.asd";
            String indexEnc = folderPath + "/index.enc";
            String index = "";
            

            try{
                index = new String(cm.getDecryptedFile(indexEnv, indexEnc, this.privateKey), StandardCharsets.UTF_8);
                
                File fileSig = new File(indexAsd);
                byte[] indexsig = Files.readAllBytes(fileSig.toPath());
                byte[] indexBytes = index.getBytes();

                if(!cm.validateFile(indexBytes, indexsig, this.publicKey)){
                    db.addLog(8008, this.login);
                    System.out.println("O arquivo index nao passou pelo teste de integridade.");    
                }
                db.addLog(8005, this.login);
                db.addLog(8006, this.login);
            }
            catch(IOException e){
                db.addLog(8004, this.login);
                System.out.println("\nCaminho da pasta errado");
                continue;
            }
            catch(Exception e){
                db.addLog(8007, this.login);
                System.out.println("\nErro decriptando o arquivo");
                continue;
            }
            
            String[] indexLines = index.split("\n");
            for(int i = 0; i<indexLines.length; i++){
                System.out.println( "[" + (i+1) +"] - " + indexLines[i]);
            }  
            db.addLog(8009, this.login);
            System.out.println("\nSelecione o arquivo desejado:");
            int op = 0;
            while(!isValid){
                String option = this.scanner.next();
                try{
                    op = Integer.parseInt(option);
                }
                catch(Exception e){
                    System.out.println("Comando invalido");
                    continue;
                }
                
                if(op<=indexLines.length && op>= 0){
                    isValid = true;
                }
                else{
                    System.out.println("\nOpcao invalida");
                }
            } 
            isValid = false;         

            String selectedLine = indexLines[op - 1];
            String fileCode = selectedLine.split(" ")[0];
            String secretName = selectedLine.split(" ")[1];
            String userLogin = selectedLine.split(" ")[2];
            String group = selectedLine.split(" ")[3];
            db.addLog(8010, this.login, fileCode); 

            if(db.getUserGroup(this.login).equals(group) || this.login.equals(userLogin)){
                db.addLog(8011, this.login, fileCode); 
                String fileEnv = folderPath + "/" + fileCode + ".env";
                String fileAsd = folderPath + "/" + fileCode + ".asd";
                String fileEnc = folderPath + "/" + fileCode + ".enc";
                
                byte[] fileBytes = cm.getDecryptedFile(fileEnv, fileEnc, this.privateKey);

                File fileSig = new File(fileAsd);
                byte[] filesig = Files.readAllBytes(fileSig.toPath());

                if(!cm.validateFile(fileBytes, filesig, this.publicKey)){
                    db.addLog(8016, this.login, fileCode);
                    System.out.println("O arquivo " + fileCode + " nao passou pelo teste de integridade.");    
                }

                try{
                    db.addLog(8013, this.login, fileCode); 
                    db.addLog(8014, this.login, fileCode); 
                    System.out.println("\nArquivo decriptado e salvo com nome "+ secretName);
                    FileOutputStream out = new FileOutputStream(secretName);
                    out.write(fileBytes);
                    out.close();
                }   
                catch(BadPaddingException e){
                    db.addLog(8015, this.login, fileCode);
                    System.out.println("Erro decriptando o arquivo " + fileCode);
                }
                catch(Exception e){
                    System.out.println("Erro salvando o arquivo");
                }
                
            }
            else{
                db.addLog(8012, this.login, fileCode); 
                System.out.println("\nUsuario nao tem permissao para acessar esse arquivo");
            }
            db.increaseTotalSearchCount(this.login);
        }
    }

    public void exitSystemMenu() throws Exception{
        db.addLog(9001, this.login);
        while(true){
            header();
            bodyOneMainMenu();
            System.out.println("\nAperte [1] para Sair do Sistema e [2] para voltar ao Menu Principal.");
            String selected = this.scanner.next();
            switch(selected){
                case "1":
                    this.scanner.close();
                    db.addLog(9002, this.login);
                    db.closeConnection(); 
                    System.exit(0);
                    break;
                case "2":
                    db.addLog(9003, this.login);
                    MainMenu();
                    break;
                default:
                    System.out.println("\nOpcao invalida");
            }
        }
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
        // String adminCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
        // String userCertPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-x509.crt";
        // String userPrivateKeyPath = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Keys/user01-pkcs8-des.key";
        // String indexEnv = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.env";
        // String indexEnc = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.enc";
        // String indexAsd = "C:/Users/gab_g/Desktop/SegurancaT4/Pacote-T4/Files/index.asd";
        
        DigitalVault dv;
        CypherManager cp = new CypherManager();
        
        
        try {
            
            db.getConn();
            db.createNewTables();
            dv = new DigitalVault();
            dv.firstStep();

            dv.scanner.close();
            db.closeConnection();            
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }
}