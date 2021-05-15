import java.io.FileOutputStream;
import java.sql.Connection;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.Statement;
import java.text.SimpleDateFormat;

public class LogView {
    private static DatabaseManager db = new DatabaseManager();

    public static void generateLog() throws Exception{
        Connection c = db.getConn();
        String login = "";
        String mensagem = "";
        String arq_name = "";
        Date date;
        String formatedDate;
        FileOutputStream out = new FileOutputStream("log.txt");
        
        c.setAutoCommit(false);

        String sql = "SELECT * FROM Registros INNER JOIN MENSAGENS ON MENSAGENS.ID = REGISTROS.ID ORDER BY TIMESTAMP ASC ;";
        Statement stmt = c.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        
        while(rs.next()){
            login = rs.getString("LOGIN");
            mensagem = rs.getString("MESSAGE");
            arq_name = rs.getString("ARQNAME");
            date = rs.getDate("TIMESTAMP");
            formatedDate = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(date);
            if(login != null && arq_name != null){
                mensagem = mensagem.replace("<login_name>", login);
                mensagem = mensagem.replace("<arq_name>", arq_name);
            }
            else if(login != null){
                mensagem = mensagem.replace("<login_name>", login);
            }
            mensagem = formatedDate + " - " +  mensagem + "\n";
            out.write(mensagem.getBytes("UTF-8"));
            
            System.out.println(mensagem + " - " + formatedDate);            
        }
        out.close();
    }

    //javac LogView.java DatabaseManager.java
    //java -cp ".;sqlite-jdbc-3.23.1.jar" LogView 
    public static void main (String[] args){

        try {
            generateLog();
        } catch (Exception e) {
            e.printStackTrace();
        }
              
    }    
}
