import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.StringTokenizer;

public final class Webserver {

  public static void main(String[] args) throws IOException {
    int port = 8000;
    ServerSocket server = new ServerSocket(port);
    System.out.println("Opening Web Server and readyto connections...");
    Socket client = null;
    while (true) {
      client = server.accept();
      System.out.println("Connect..." + client.toString());
      Handler request = new Handler(client);
      Thread thread = new Thread(request);
      thread.start();
    }
  }
}
	
class Handler implements Runnable {
	private Socket clientSocket;

	  public Handler(Socket c) {
	    this.clientSocket = c;
	  }

	  public void run() {
	    boolean check = true;
	    try {
	    InputStream input = clientSocket.getInputStream();
	    OutputStream output = clientSocket.getOutputStream();
	    BufferedReader br = new BufferedReader(new InputStreamReader(input));
	    String line = br.readLine();
	    System.out.println(line);
	    StringTokenizer tokens = new StringTokenizer(line);

	      if (!tokens.nextToken().toUpperCase().equals("GET")) {
	        check = false;
	      }
	      String string = null;
	      if (check) {
	    	  String fileName = tokens.nextToken();
		        fileName = fileName.substring(1);
		        string = fileName;
		      }
		      PrintWriter out = new PrintWriter(output);
		      if (check) {
		        out.println("HTTP/1.0 200 OK");
		        printMessage("Sending " + 100+string.length() + " bytes");
		        printHTML(out, string);
		        printMessage(100+string.length() + " bytes sent");
		      } else {
		        printMessage("Client Bad Request response message sent.");
		        out.println("HTTP/1.0 400 Bad Request");
		        out.println();
		        out.print("Bad Request.");
		      }

		      out.close();
		      output.close();
		      br.close();
		      input.close();
	      
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
	    }
	  }

	  public void printMessage(String message) {
	    System.out.println(message + " |port: " + clientSocket.getPort());
	  }

	  private void printHTML(PrintWriter out, String numOfBytes) {
	    out.println("Content-Type: text/html");
	    out.println("Content-Length: " + 100+numOfBytes.length());
	    out.println();
	    out.println("<HTML>");
	    out.println("<HEAD>");
	    out.println("<TITLE>This is " + 100+numOfBytes.length() + " bytes long :)</TITLE>");
	    out.println("</HEAD>");
	    out.print("<BODY>");  
	    out.print(numOfBytes);
	    out.println("</BODY>");
	    out.print("</HTML>");
	  }
	}
