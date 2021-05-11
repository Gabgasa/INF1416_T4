import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.Base64;




public class DatabaseManager {
    private String PathToDB;

    DatabaseManager (String pathDB) {
        PathToDB = pathDB;
    }

    public void createNewTables() throws Exception{
        String url = "jdbc:sqlite:" + PathToDB;
        
        Connection conn = DriverManager.getConnection(url);
        // System.out.println("Connection succesful");
        Statement stmt = conn.createStatement();
        String sql =    "CREATE TABLE IF NOT EXISTS USUARIOS " +
                        "(LOGIN TEXT PRIMARY KEY     NOT NULL," +
                        " NAME           TEXT    NOT NULL, " + 
                        " CERT           TEXT     NOT NULL, " + 
                        " ALGORITHM      TEXT, " +
                        " SALT      TEXT NOT NULL," +                     
                        " PASSWORD       TEXT   NOT NULL)";

        stmt.executeUpdate(sql);

        sql =   "CREATE TABLE IF NOT EXISTS GRUPOS " +
                "(GID INT PRIMARY KEY     NOT NULL," +
                " GROUPNAME           TEXT    NOT NULL)";
                
        stmt.executeUpdate(sql);

        sql =   "CREATE TABLE IF NOT EXISTS MENSAGENS " +
                "(ID INT PRIMARY KEY     NOT NULL," +
                " MESSAGE           TEXT    NOT NULL)"; 
        
        stmt.executeUpdate(sql);
        
        sql =   "CREATE TABLE IF NOT EXISTS REGISTROS " +
                "(ID CHAR(100) PRIMARY KEY     NOT NULL," +
                "USER           TEXT  ," +
                "FOREIGN KEY (USER) REFERENCES Usuarios(LOGIN))";
        stmt.executeUpdate(sql);
        stmt.close();
        conn.close();
    }

    public boolean findIfUserExists(String login) throws Exception{
        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        System.out.println("Connection succesful");

        conn.setAutoCommit(false);

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM USUARIOS WHERE LOGIN=" + "'" + login + "';");
        if(rs.next()){
            rs.close();
            stmt.close();
            conn.close();
            return true;
        }
        
        rs.close();
        stmt.close();
        conn.close();
        return false;
    }

    public void insertField() throws Exception{
        
        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        // System.out.println("Connection succesful");
        Statement stmt = conn.createStatement();
        String sql = "INSERT INTO USUARIOS (LOGIN,NAME,CERT,ALGORITHM,SALT,PASSWORD)" +
        "VALUES ('gabgasa@hotmail.com', 'Gabriel Aquino', 'aaassdada', 'HASH_SHA1', 'abcde', 'abc123');";   
        stmt.executeUpdate(sql);
        stmt.close();
        conn.close();

    }

    public void removeUser(String login) throws Exception{     
        String url = "jdbc:sqlite:" + PathToDB;       
        Connection conn = DriverManager.getConnection(url);
        // System.out.println("Connection succesful");
        Statement stmt = conn.createStatement();
        String sql = "DELETE FROM USUARIOS WHERE LOGIN='" + login +"';"; 

        stmt.executeUpdate(sql);
        stmt.close();
        conn.close();
    
    }
    

    public void insertNewUser(String login, String name, String cert, String algorithm, String salt, String hexPassword) throws Exception{
        
        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        // System.out.println("Connection succesful");
        Statement stmt = conn.createStatement();
        String sql = "INSERT INTO USUARIOS (LOGIN,NAME,CERT,ALGORITHM,SALT,PASSWORD)" +
                    "VALUES ('" + login + "', '" + name + "', '" + cert + "', '" + algorithm + "', '" + salt + "', '" + hexPassword + "');";

        stmt.executeUpdate(sql);
        stmt.close();
        conn.close();

    }

    public String getUserName(String login) throws Exception{
        String name = "";
        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        //System.out.println("Connection succesful");

        conn.setAutoCommit(false);

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM USUARIOS WHERE LOGIN=" + "'" + login + "';");

        while(rs.next()){
            name = rs.getString("NAME");
        }
        rs.close();
        stmt.close();
        conn.close();
        return name;
    }

    public X509Certificate getDigitalCert(String login) throws Exception{
        String cert = "";
        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        //System.out.println("Connection succesful");

        conn.setAutoCommit(false);

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM USUARIOS WHERE LOGIN=" + "'" + login + "';");

        while(rs.next()){
            cert = rs.getString("CERT");
        }
        rs.close();
        stmt.close();
        conn.close();

        String newC = cert.replace("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll("\n", "")
                        .replace("-----END CERTIFICATE-----", "");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        byte[] decoded = Base64.getDecoder().decode(newC);
        
        // ByteArrayInputStream certBytes = new ByteArrayInputStream(decoded);
        X509Certificate ce = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decoded));
       
        return ce;
    }

    public String getPasswordSalt(String login) throws Exception{
        String salt = "";

        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        //System.out.println("Connection succesful");

        conn.setAutoCommit(false);

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM USUARIOS WHERE LOGIN=" + "'" + login + "';");

        while(rs.next()){
            salt = rs.getString("SALT");
        }
        rs.close();
        stmt.close();
        conn.close();
        return salt;
    }

    public String getPasswordHex(String login) throws Exception{
        String password = "";

        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        //System.out.println("Connection succesful");

        conn.setAutoCommit(false);

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM USUARIOS WHERE LOGIN=" + "'" + login + "';");

        while(rs.next()){
            password = rs.getString("PASSWORD");
        }
        rs.close();
        stmt.close();
        conn.close();
        return password;
    }

    public String getPasswordHashAlgorithm(String login) throws Exception{
        String algorithm = "";

        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        //System.out.println("Connection succesful");

        conn.setAutoCommit(false);

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM USUARIOS WHERE LOGIN=" + "'" + login + "';");

        while(rs.next()){
            algorithm = rs.getString("ALGORITHM");
        }
        rs.close();
        stmt.close();
        conn.close();
        return algorithm;
    }

// //java -cp ".;sqlite-jdbc-3.23.1.jar" DatabaseManager
//     public static void main(String[] args) {
        
//         DatabaseManager db = new DatabaseManager("test.db");
        
//         try {
//             db.createNewTables();
//             //db.insertField();
//             //"VALUES ('" + login + "', '" + name + "', '" + cert + "', '" + algorithm + "', '" + salt + "', '" + hexPassword + "');";
//             db.insertNewUser("gabgasa01@gmail.com", "Gabriel Aquino", "aaaaaa", "SHA256", "1EIASJE", "senha123");
//         } catch (Exception e) {
//             e.printStackTrace();
//             System.exit(0);
//         }

//     }
}