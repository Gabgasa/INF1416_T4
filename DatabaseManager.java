import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.Base64;
import java.util.Date;




public class DatabaseManager {
    private static Connection c = null;

    DatabaseManager () {
    }

    public Connection getConn() throws Exception{
        if(c == null){
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:digitalvault.db");
        }

        return c;
    }
    
    public void closeConnection() throws Exception{
        c.close();
    }

    public void createNewTables() throws Exception{
        // System.out.println("Connection succesful");
        
        Statement stmt = c.createStatement();
        String sql =    "CREATE TABLE IF NOT EXISTS USUARIOS " +
                        "(LOGIN TEXT PRIMARY KEY     NOT NULL," +
                        " NAME           TEXT    NOT NULL, " + 
                        " CERT           TEXT     NOT NULL, " + 
                        " ALGORITHM      TEXT, " +
                        " SALT      TEXT NOT NULL," +                     
                        " PASSWORD       TEXT   NOT NULL," +
                        " GID       TEXT   NOT NULL," +
                        " ACCESSCOUNT INT NOT NULL," +
                        " SEARCHCOUNT INT NOT NULL," +
                        " BLOCKCOUNT INT NOT NULL," +
                        " LASTBLOCKED DATETIME, " + 
                        " FOREIGN KEY (GID) REFERENCES GRUPOS(GID))";

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
                "(ID INT NOT NULL ,"+ 
                "LOGIN           TEXT  ," +
                "ARQNAME           TEXT  ," +
                "TIMESTAMP DATETIME NOT NULL," + 
                "FOREIGN KEY (ID) REFERENCES MENSAGENS(ID))";
        stmt.executeUpdate(sql);
        stmt.close();
    }

    public boolean checkIfUserExists(String login) throws Exception{       
        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);
        ResultSet rs = stmt.executeQuery();
        
        if(rs.next()){
            rs.close();
            stmt.close();
            return true;
        }
        
        rs.close();
        stmt.close();
        return false;
    }

    public String getUserGroup(String login) throws Exception{
        String group = "";

        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM GRUPOS INNER JOIN USUARIOS ON GRUPOS.GID = USUARIOS.GID AND USUARIOS.LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);
        ResultSet rs = stmt.executeQuery();
        
        if(rs.next()){
            group = rs.getString("GROUPNAME");
        }
        
        rs.close();
        stmt.close();

        return group;
    }

    public boolean checkIfUserBlocked(String login) throws Exception{
        c.setAutoCommit(false);
        Date aux = new Date();
        java.sql.Date now = new java.sql.Date(aux.getTime());
        java.sql.Date lastblocked = null;
        long difference = 0;

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);
        ResultSet rs = stmt.executeQuery();

        while(rs.next()){
            lastblocked = rs.getDate("LASTBLOCKED");
        }

        if(lastblocked != null){//Nunca foi bloqueado
            difference = now.getTime() - lastblocked.getTime();
            
            if(difference <= 120000){//miliseconds
                return true; //Continua bloqueado
            }
        }   
        return false; //Nao estah bloqueado
    }

    public void blockUser(String login) throws Exception{
        //System.out.println("Connection succesful");
        Date aux = new Date();
        java.sql.Date now = new java.sql.Date(aux.getTime());

        c.setAutoCommit(false);
        String sql = "UPDATE USUARIOS set BLOCKCOUNT = 0, LASTBLOCKED = ? WHERE LOGIN = ?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setDate(1, now);
        stmt.setString(2, login);
        
        stmt.executeUpdate();
        c.commit();
        
        stmt.close();
    }

    public int getTotalUsers() throws Exception{
        c.setAutoCommit(false);
        int count = 0;

        String sql = "SELECT * FROM USUARIOS;";
        Statement stmt = c.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        
        while(rs.next()){
            count++;
        }
        
        return count;
    }

    public void removeUser(String login) throws Exception{          
        // System.out.println("Connection succesful");
        c.setAutoCommit(false);
        String sql = "DELETE FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);
        c.commit();
        stmt.executeUpdate();
        
        stmt.close();    
    }
    

    public void insertNewUser(String login, String name, String cert, String algorithm, String salt, String hexPassword, String gid, String accesscount, String searchcount, String blockcount) throws Exception{
             
        // System.out.println("Connection succesful");
        c.setAutoCommit(false);
        String sql = "INSERT INTO USUARIOS (LOGIN,NAME,CERT,ALGORITHM,SALT,PASSWORD, GID, ACCESSCOUNT, SEARCHCOUNT, BLOCKCOUNT)" +
                        "VALUES (?,?,?,?,?,?,?,?,?,?)";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);
        stmt.setString(2, name);
        stmt.setString(3, cert);
        stmt.setString(4, algorithm);
        stmt.setString(5, salt);
        stmt.setString(6, hexPassword);
        stmt.setInt(7, Integer.parseInt(gid));
        stmt.setInt(8, Integer.parseInt(accesscount));
        stmt.setInt(9, Integer.parseInt(searchcount));
        stmt.setInt(10, Integer.parseInt(blockcount));

        stmt.executeUpdate();
        c.commit();
        stmt.close();
    }

    public int getFailAttemptsCount(String login) throws Exception{
        int blockcount = 0;
        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);
        
        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            blockcount = rs.getInt("BLOCKCOUNT");
        }

        
        rs.close();
        stmt.close();

        return blockcount;
    }

    public int getTotalSearchCount(String login) throws Exception{
        int searchCount = 0;

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);
        
        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            searchCount = rs.getInt("SEARCHCOUNT");
        }        
        rs.close();
        stmt.close();

        return searchCount;
    }
    public int increaseTotalSearchCount(String login) throws Exception{
        int searchCount = getTotalSearchCount(login);

        c.setAutoCommit(false);
        searchCount += 1;

        String sql = "UPDATE USUARIOS set SEARCHCOUNT = ? WHERE LOGIN = ?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setInt(1, searchCount);
        stmt.setString(2, login);
        
        stmt.executeUpdate();
        c.commit();
        
        stmt.close();
        return searchCount;
    }

    public void addLog(int gid, String login, String arq_name) throws Exception{
        // System.out.println("Connection succesful");
        Date aux = new Date();
        java.sql.Date now = new java.sql.Date(aux.getTime());

        c.setAutoCommit(false);
        String sql = "INSERT INTO REGISTROS (ID, LOGIN, ARQNAME, TIMESTAMP)" +
                        "VALUES (?,?,?,?)";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setInt(1, gid);
        stmt.setString(2, login);
        stmt.setString(3, arq_name);
        stmt.setDate(4, now);
        

        stmt.executeUpdate();
        c.commit();
        stmt.close();
    }
    //OVERLOAD
    public void addLog(int gid, String login) throws Exception{
        // System.out.println("Connection succesful");
        Date aux = new Date();
        java.sql.Date now = new java.sql.Date(aux.getTime());

        c.setAutoCommit(false);
        String sql = "INSERT INTO REGISTROS (ID, LOGIN, TIMESTAMP)" +
                        "VALUES (?,?,?)";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setInt(1, gid);
        stmt.setString(2, login);
        stmt.setDate(3, now);
        

        stmt.executeUpdate();
        c.commit();
        stmt.close();
    }
    //OVERLOAD
    public void addLog(int gid) throws Exception{
        // System.out.println("Connection succesful");
        Date aux = new Date();
        java.sql.Date now = new java.sql.Date(aux.getTime());

        c.setAutoCommit(false);
        String sql = "INSERT INTO REGISTROS (ID,TIMESTAMP)" +
                        "VALUES (?,?)";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setInt(1, gid);
        stmt.setDate(2, now);
        

        stmt.executeUpdate();
        c.commit();
        stmt.close();
    }

    // public String[] getLogs() throws Exception{
    //     String[] logs;

    //     c.setAutoCommit(false);

    //     String sql = "SELECT * FROM REGISTROS ORDER BY datetime(TIMESTAMP) ASC ";
    //     Statement stmt = c.prepareStatement(sql);

    //     ResultSet rs = stmt.executeQuery(sql);
    //     while(rs.next()){
    //         accessCount = rs.getInt("ACCESSCOUNT");
    //     }
    //     rs.close();
    //     stmt.close();
    //     return Integer.toString(accessCount);
    // }

    public void increaseFailAttemptsCount(String login, int block) throws Exception{
        //System.out.println("Connection succesful");

        c.setAutoCommit(false);
        block += 1;

        String sql = "UPDATE USUARIOS set BLOCKCOUNT = ? WHERE LOGIN = ?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setInt(1, block);
        stmt.setString(2, login);
        

        stmt.executeUpdate();
        c.commit();
        
        stmt.close();
    }

    public String getUserTotalAccess(String login) throws Exception{
        int accessCount = 0;

        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);

        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            accessCount = rs.getInt("ACCESSCOUNT");
        }
        rs.close();
        stmt.close();
        return Integer.toString(accessCount);
    }

    public void addUserTotalAccess(String login) throws Exception{
        //System.out.println("Connection succesful");
        c.setAutoCommit(false);
        int accessCount = Integer.parseInt(getUserTotalAccess(login));
        String sql = "UPDATE USUARIOS SET ACCESSCOUNT=? WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setInt(1, accessCount + 1);
        stmt.setString(2, login);
        stmt.executeUpdate();

        c.commit();
        stmt.close();
    }

    public void changeUserPassword(String login, String salt, String hexPassword) throws Exception{
        //System.out.println("Connection succesful");
        String sql = "UPDATE USUARIOS SET PASSWORD=?, SALT=? WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, hexPassword);
        stmt.setString(2, salt);
        stmt.setString(3, login);
        stmt.executeUpdate();

        c.commit();
        stmt.close();
    }

    public void changeUserCertificate(String login, String PEMCert) throws Exception{
        //System.out.println("Connection succesful");
        String sql = "UPDATE USUARIOS SET CERT=? WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, PEMCert);
        stmt.setString(2, login);

        stmt.executeUpdate();

        c.commit();
        stmt.close();
    }

    public String getUserName(String login) throws Exception{
        String name = "";

        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);

        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            name = rs.getString("NAME");
        }
        rs.close();
        stmt.close();
        return name;
    }

    public X509Certificate getDigitalCert(String login) throws Exception{
        String cert = "";
        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);

        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            cert = rs.getString("CERT");
        }
        rs.close();
        stmt.close();

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
        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);

        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            salt = rs.getString("SALT");
        }
        rs.close();
        stmt.close();
        return salt;
    }

    public String getPasswordHex(String login) throws Exception{
        String password = "";
        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);

        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            password = rs.getString("PASSWORD");
        }
        rs.close();
        stmt.close();
        return password;
    }

    public String getPasswordHashAlgorithm(String login) throws Exception{
        String algorithm = "";
        //System.out.println("Connection succesful");

        c.setAutoCommit(false);

        String sql = "SELECT * FROM USUARIOS WHERE LOGIN=?";
        PreparedStatement stmt = c.prepareStatement(sql);
        stmt.setString(1, login);

        ResultSet rs = stmt.executeQuery();
        while(rs.next()){
            algorithm = rs.getString("ALGORITHM");
        }
        rs.close();
        stmt.close();
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