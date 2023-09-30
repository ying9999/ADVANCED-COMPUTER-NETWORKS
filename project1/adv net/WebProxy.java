import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;

public class WebProxy {
    public static void main(String[] args) throws Exception {
        ServerSocket server = new ServerSocket(8080);
        System.out.println("Proxy Server start 8080");

        while (true) {
            Socket socket = server.accept();
            new Thread (new MHandler(socket)).start();
        }
    }
}

class MHandler implements Runnable {
	 Socket s;

	 MHandler(Socket s) {
	        this.s = s;
	    }

	    public void run() {
	        try {
	            
	            DataOutputStream output = new DataOutputStream(s.getOutputStream());
	            BufferedReader read = new BufferedReader(new InputStreamReader((s.getInputStream())));

	            Request request = new Request(read);

	            if (!"GET".equals(request.method)) { 
	                s.close();
	                return;
	            }
	                System.out.println("//" + request);

	                Response r = request.getResponse();

	            if (r != null)
	                r.send(output);
	            read.close();
	            output.close();

	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	        try {
	            s.close();
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
	}

class Response implements Runnable {
	ArrayList<String> line1 = new ArrayList<>();

	Response(BufferedReader read) throws Exception {
        String line;
        while ((line = read.readLine()) != null) {
            line1.add(line);
        }
    }
    void send(DataOutputStream out) throws IOException {
        for (String line : line1) {
            System.out.println(line);
            out.writeBytes(line + "\r\n");
            out.flush();
        }
        out.writeBytes("\r\n");
        out.flush();
    }
	public void run() {
	}
}

class Request implements Runnable {
    int port;
    String method = "GET";
    String path = "/";
    String version = "HTTP/1.0";
    final String cacheFolderPATH = "cache";
    String cacheFileName;
    HashMap<String, String> headers = new HashMap<>();
    Socket socket;
    DataOutputStream outStream;
    BufferedReader read;
    PrintWriter out;

    Request(BufferedReader reader) throws Exception {
        String rLine = reader.readLine();
        if (rLine == null) {
            throw new Exception("Invalid");
        }

        String[] split = rLine.split(" ");
        try {
        	path = split[1];
            URL url = new URL(path);
            port = url.getPort();
            cacheFileName = path.substring(1) + ".cache";
            headers.put("Host", url.getHost());
        } catch (Exception e) {
        }
    }
    private boolean checkCache() {
        File folder = new File(cacheFolderPATH);
        File[] listOfFiles = folder.listFiles();

        for (int i = 0; i < listOfFiles.length; i++) {
            if (listOfFiles[i].isFile() && listOfFiles[i].getName().equals(cacheFileName)) {
                return true;
            }

        }
        return false;
    }

    Response getResponse() throws Exception {
        boolean isCached = checkCache(); 
        System.out.println(isCached);
        if (!isCached) {
            try {
                socket = new Socket("localhost", 8000); 
                outStream = new DataOutputStream(socket.getOutputStream());
                read = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(outStream);
            } catch (Exception e) {

            } 
            write(method + " " + path + " " + version); 
            for (String key : headers.keySet()) {
                write(key + ": " + headers.get(key));
            }
            write("");
            Response response = new Response(read);
            File fileToCache = new File(cacheFolderPATH + "\\" + cacheFileName);
            FileOutputStream fileOutStream = new FileOutputStream(fileToCache);
            DataOutputStream outData = new DataOutputStream(fileOutStream);
            response.send(outData);
            return response;
        } else {
            File cacheFile = new File(cacheFolderPATH + "\\" + cacheFileName);
            InputStream fileStream = new FileInputStream(cacheFile);
            BufferedReader cacheFileReader = new BufferedReader(new InputStreamReader(fileStream));
            Response cacheResponse = new Response(cacheFileReader);
            return cacheResponse;
        }
    }
    private void write(String line) throws Exception {
        System.out.println(line);
        out.println(line + "\r\n");
        out.flush();
    }
	public void run() {
	}
}
