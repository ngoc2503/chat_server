package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import util.AESUtil;
import util.Command;
import util.Mail;
import util.RSAUtil;
import util.Request;
import util.Response;
import util.SignatureUtil;
import util.TcpChannel;

public class UserProcessor {
	private static final String SIG_HEADER = "SIG:";
	private static final String KEY = "KEY:";
	private static final String BODY = "BODY:";
	private Socket socket;
	private Request request;
	private Response response;
	private TcpChannel channel;
	
	public UserProcessor(Socket sock){
		this.socket = sock;
		try {
			channel = new TcpChannel(socket);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public int process() throws IOException{
		String command = request.getCommand();
		channel.sendRequest(request);
		response = channel.receiveResponse();
		if(response != null){
			handleResponse(command);
			return 0;
		}
		else return -1;
	}
	
	public void setResponse(Response res){
		this.response = res;
	}
	
	public void setRequest(Request req){
		this.request = req;
	}
	
	private void handleResponse(String command) throws IOException{
		System.out.println("Receive: " + response.craftToString());
		
		String returnCode = response.getCode();
		if (returnCode.compareTo(Response.SUCCESS) == 0){
			if (command.compareToIgnoreCase(Command.DATA) == 0)
				doDataResponse();
			else if (command.compareToIgnoreCase(Command.LIST) == 0)
				doListResponse();
			else if (command.compareToIgnoreCase(Command.RETRIEVE) == 0)
				doRetrieveResponse();
		}
	}
	
	private void doDataResponse() throws IOException{
		System.out.println("Send: ");
		BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
		StringBuilder builder = new StringBuilder();
		String line;
		boolean isLine = false;
		do {
			line = user.readLine();
			if(line.compareToIgnoreCase(Mail.END_MAIL) == 0) {
				isLine = true;
				break;
			}
			builder.append(line +"\n");
		}while(true);
		// thong tin email truoc khi gui di
		String message = builder.toString().trim();
		// Sinh khoa aes
		SecureRandom random = new SecureRandom();
		String password = String.valueOf(random.nextInt());
		AESUtil aesCryptor = new AESUtil();
		SecretKey key;
		try {
			key = aesCryptor.getSecretKey(password);
			// ma hoa thong diep email bang AES
			message = aesCryptor.encryptString((SecretKey) key, message);
			// ma hoa AES bang RSA
			String encryptKey = enCryptKeyAES(user, password);
			// Tao chu ky so bang RSA
			String dataSend = dataSignature(user, message, encryptKey);
			channel.sendRequest(new Request(dataSend));
		} catch (GeneralSecurityException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		if(isLine) channel.sendRequest(new Request(line));
		response = channel.receiveResponse();
		System.out.println(response.craftToString());		
	}
	
	private void doListResponse() throws IOException{
		StringBuilder builder = new StringBuilder();
		int numberOfMail = Integer.parseInt(response.getNotice());
		for(int i = 0; i < numberOfMail; i++)
			builder.append(channel.receiveLine());
		System.out.println(builder.toString());
	}
	
	private void doRetrieveResponse() throws IOException{
		StringBuilder builder = new StringBuilder();
		String line;
		int leftBytes = Integer.parseInt(response.getNotice()) + 1;
		while(leftBytes > 0){
			line = channel.receiveLine();
			builder.append(line);
			leftBytes = leftBytes - line.length();
		}
		System.out.println(builder.toString());
	}
	/**
	 * 
	 * @param red
	 * @param keyString
	 * @return key duoc ma hoa bang thuat toan RSA
	 */
	private String enCryptKeyAES(BufferedReader red, String keyString) {
		RSAUtil rsaCryptor = new RSAUtil();
		RSAKeyParameters publicKey;
		String publicKeyFile;
		System.out.print("Server certificate file: ");
		try {
			publicKeyFile = red.readLine();
			publicKey =  rsaCryptor.getPublicKey(publicKeyFile);
			keyString = rsaCryptor.encryptString(publicKey, keyString);
		} catch (IOException | InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyString;
	}
	/**
	 * Insert signature into message
	 * @param message
	 * @param password
	 * @return 
	 */
	private String dataSignature(BufferedReader red, String message, String encryptKey) {
		SignatureUtil signOperator = new SignatureUtil();
		RSAKeyParameters senderPrivateKey;
		String senderPrivateKeyFile;
		String signature = "";
		System.out.print("Enter private key file: ");
		
		try {
			senderPrivateKeyFile = red.readLine();
			System.out.print("Enter the passord using private key: ");
			String password = red.readLine();
			senderPrivateKey = signOperator.getPrivateKey(senderPrivateKeyFile, password);
			signature = signOperator.signString(senderPrivateKey, message);
		
		} catch (IOException | OperatorCreationException | PKCSException | DataLengthException | CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		StringBuilder builder = new StringBuilder();
		//Encapsulate SIG header
		builder.append(SIG_HEADER + signature + " ");
		builder.append(KEY + encryptKey + " ");
		builder.append(BODY + message);
		return builder.toString();
	}
}

