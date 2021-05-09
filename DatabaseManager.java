import java.sql.*;



public class DatabaseManager {
    private String PathToDB;

    DatabaseManager (String pathDB) {
        PathToDB = pathDB;
    }

    public void createNewTables() throws Exception{

        String url = "jdbc:sqlite:" + PathToDB;
        
        Connection conn = DriverManager.getConnection(url);
        System.out.println("Connection succesful");
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

    public void insertField() throws Exception{
        
        String url = "jdbc:sqlite:" + PathToDB;        
        Connection conn = DriverManager.getConnection(url);
        System.out.println("Connection succesful");
        Statement stmt = conn.createStatement();
        String sql = "INSERT INTO USUARIOS (LOGIN,NAME,CERT,ALGORITHM,SALT,PASSWORD)" +
        "VALUES ('gabgasa@hotmail.com', 'Gabriel Aquino', 'aaassdada', 'HASH_SHA1', 'abcde', 'abc123');";   
        stmt.executeUpdate(sql);
        stmt.close();
        conn.close();

    }

//java -cp ".;sqlite-jdbc-3.23.1.jar" DatabaseManager
    public static void main(String[] args) {
        
        DatabaseManager db = new DatabaseManager("test.db");
        
        try {
            db.createNewTables();
            db.insertField();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}