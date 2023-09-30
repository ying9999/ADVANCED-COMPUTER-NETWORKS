import java.io.*;
import java.net.*;


public class Webclient {

	public static void main(String[] args) throws IOException {
        Socket cSocket = new Socket("localhost", 8080);
        OutputStream output = cSocket.getOutputStream();
        InputStream input = cSocket.getInputStream();
        output.write("GET /100 HTTP/1.1\r\n".getBytes());
        output.write("Host: localhost\r\n".getBytes());
        output.write("\r\n".getBytes());
        output.flush();

        BufferedReader read = new BufferedReader(new InputStreamReader(input));
        String line = read.readLine();
        while (line != null) {
            System.out.println(line);
            line = read.readLine();
        }   
        cSocket.close();
	}
}
