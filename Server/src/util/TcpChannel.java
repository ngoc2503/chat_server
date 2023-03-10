package util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;

public class TcpChannel {
	private Socket socket;
	private BufferedReader in;
	private PrintWriter out;
	private int status;

	public TcpChannel(Socket s) throws IOException {
		this.socket = s;
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
		status = -1;
	}

	public int sendResponse(Response response) {
		String message = response.craftToString();

		out.println(message);
		out.flush();
		System.out.println("Send: " + message);
		return message.length();
	}


	public Request receiveRequest() throws IOException {
		String message = new String();
		
		if ((message=in.readLine()) != null){
				if(status != 1)
				System.out.println("Receive: " + message);
				
				Request request = new Request(message);
				if(request.getCommand().equalsIgnoreCase(Command.DATA)) status = 1;
				if(request.getCommand().equalsIgnoreCase(Command.MAIL)) status = -1;
				return request;
		}
		else 
			return null;		
	}
}
