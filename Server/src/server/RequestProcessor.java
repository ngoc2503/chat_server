package server;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import util.AESUtil;
import util.Command;
import util.Database;
import util.Mail;
import util.RSAUtil;
import util.Request;
import util.Response;
import util.SignatureUtil;

public class RequestProcessor{ 
	private static final String SIG_HEADER = "SIG:";
	private static final String KEY = "KEY:";
	private static final String BODY = "BODY:";
	private Request request;
	private Response response;
	private Mail mail;
	private Session session;
	private Database db;
	
	public RequestProcessor(){
		session = new Session();
		request = new Request();
		try {
			db = new Database(Database.DB_NAME, Database.ACCOUNT, Database.PASSWORD);
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
	
	public int process(){
		int ret = 0;
		
		if(session.getStatus() == Session.RECEIVING_MAIL) {
			receiveMail();
			
		}
			
		else{			
			String command = request.getCommand();
			if(command.compareTo(Command.DATA) == 0)
				doData();
			else if(command.compareTo(Command.DELETE) == 0)
				doDelete();
			else if(command.compareTo(Command.HELLO) == 0)
				doHello();
			else if(command.compareTo(Command.LIST) == 0)
				doList();
			else if(command.compareTo(Command.MAIL) == 0)
				doMail();
			else if(command.compareTo(Command.QUIT) == 0)
				ret = doQuit();
			else if(command.compareTo(Command.RETRIEVE) == 0)
				doRetrieve();
			else 
				doWrong();
		}			
			
		return ret;
	}
	
	public void doData(){
		response = new Response();
		if(session.getStatus() == Session.RECIPIENT_IDENTIFIED){
			mail.setTime(new Date());
			session.setStatus(Session.RECEIVING_MAIL);
			response.setContent(Response.SUCCESS, Response.DATA_SUCCESS);
		}
		else
			response.setContent(Response.ERROR, Response.BAD_SEQUENCE);
	}
	
	public void doDelete(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED){
			int foundMail = 0; 
			foundMail = db.deleteMail(session.getUser(), Integer.parseInt(request.getParameter()));
			if(foundMail != 0)
				response.setContent(Response.SUCCESS, Response.DELETE_SUCCESS);
			else response.setContent(Response.ERROR, Response.DELETE_FAIL);
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);			
	}
	
	public void doHello(){
		response = new Response();
		session.setUser(request.getParameter());			
		response.setContent(Response.SUCCESS, Response.HELLO_SUCCESS);
	}
	
	public void doList(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED){
			ArrayList<Mail> list = new ArrayList<Mail>();
			list = db.retrieveMailList(session.getUser());
			StringBuilder result = new StringBuilder();
			int size = list.size();
			result.append(size);
			for(Mail mail : list){
				result.append("\n");
				result.append(mail.getId());
				result.append(" ");
				DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy hh:mm:ss");
				result.append(dateFormat.format(mail.getReceivedTime()));
				result.append(" ");
				result.append(mail.getSender());				
			}
			response.setContent(Response.SUCCESS, result.toString());
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);
			
	}
	
	public void doMail(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED || session.getStatus() == Session.RECIPIENT_IDENTIFIED){
			session.setStatus(Session.RECIPIENT_IDENTIFIED);
			mail = new Mail();
			mail.setSender(session.getUser());
			mail.setRecipient(request.getParameter());
			mail.setBody("");
			response.setContent(Response.SUCCESS, Response.MAIL_SUCCESS);
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);
	}
	
	public int doQuit(){
		return -1;
	}
	
	public void doRetrieve(){
		response = new Response();
		if(session.getStatus() == Session.USER_IDENTIFIED){
			Mail mail = db.retrieveMail(session.getUser(),Integer.parseInt(request.getParameter()));
			if(mail != null){
				StringBuilder result = new StringBuilder();
				String rawMail = mail.craftToString();
				result.append(rawMail.length());
				result.append("\n");
				result.append(rawMail);
				response.setContent(Response.SUCCESS, result.toString());				
			}
			else response.setContent(Response.ERROR, Response.RETRIEVE_FAIL);
		}
		else response.setContent(Response.ERROR, Response.BAD_SEQUENCE);				
	}
	
	public void doWrong(){
		response = new Response();
		response.setContent(Response.ERROR, Response.WRONG_SYNTAX);
	}
	
	private void receiveMail(){
		String line = request.getRaw();	
		
		// kiem tra tinh toan ven cua thong tin
		if (line.compareTo(Mail.END_MAIL) != 0){
			response = null;
			checkAndDecrypt(line);
			StringBuilder builder = new StringBuilder();
			builder.append(mail.getBody() + "\n");
			builder.append(line);
			mail.setBody(builder.toString());
		}
		else{
			response = new Response();
			String message = mail.getBody();
			response.setContent(Response.SUCCESS, Response.DELIVERY_SUCCESS);
			db.insertMail(mail);
			session.setStatus(Session.USER_IDENTIFIED);
		}
	}
	
	public void setRequest(Request req){
		this.request = req;
	}
	
	public Response getResponse(){
		return this.response;
	}

	
	// Kiem tra tinh hop le va giai ma email nhan duoc
	public void checkAndDecrypt(String reciverEmail) {
		int startKey = reciverEmail.indexOf(KEY);
		int startBody = reciverEmail.indexOf(BODY);
		String signature, keyAES, body;
		// tach lay chu ky so, key ma hoa, thong diep email
		signature = reciverEmail.substring(SIG_HEADER.length(), startKey).trim();
		keyAES = reciverEmail.substring(startKey + KEY.length(), startBody).trim();
		body = reciverEmail.substring(startBody + BODY.length());
		// kiem tra su hop le cua email
		check(signature, body);
		// giai ma khoa AES
		String AESDecrypt = decryptAES(keyAES);
		// giai ma email
		String bodyEmail = decryptEmail(AESDecrypt, body);
	}
	private void check(String sign, String mes) {
		BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
		SignatureUtil sigUtil = new SignatureUtil();
		RSAKeyParameters senderPublicKey;
		String senderPublicKeyFile;
		System.out.print("Enter public key sender file: ");
		try {
			senderPublicKeyFile = user.readLine();
			senderPublicKey = sigUtil.getPublicKey(senderPublicKeyFile);
			if(sigUtil.verifyString(senderPublicKey, mes, sign))
				System.out.println("Message is authentic");
			else
				System.out.println("Message is not authentic");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private String decryptAES(String encryptKey) {
		String result = null;
		BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
		//Import server's private key
		RSAUtil rsaCryptor = new RSAUtil();
		RSAKeyParameters serverPrivateKey;
		String serverPrivateKeyFile, keyPassword;

		System.out.print("Server private key file: ");
		try {
			serverPrivateKeyFile = user.readLine();
			System.out.print("Password for using private key: ");
			keyPassword = user.readLine();
			serverPrivateKey = rsaCryptor.getPrivateKey(serverPrivateKeyFile, keyPassword);
			result = rsaCryptor.decryptString(serverPrivateKey, encryptKey);
		} catch (IOException | OperatorCreationException | PKCSException | InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}
	// giai ma email
	private String decryptEmail(String password, String mes) {
		String message = null;
		AESUtil aesCryptor = new AESUtil();
		try {
			SecretKey key = aesCryptor.getSecretKey(password);
			message = aesCryptor.decryptString(key, mes);
		} catch (UnsupportedEncodingException | GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("message:\n" + message);
		return message;
	}
}

