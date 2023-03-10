package util;


import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;


public class RSAUtil {
	
	public RSAKeyParameters getPrivateKey(String keyFile, String password)
			throws IOException, OperatorCreationException, PKCSException{	
		RSAKeyParameters privateKey = null;
		PrivateKeyInfo keyInfo = null;
		FileReader reader = new FileReader(keyFile);
		PEMParser pemParser = new PEMParser(reader);
	    Object keyPair = pemParser.readObject();	        
	    if(keyPair instanceof PKCS8EncryptedPrivateKeyInfo){
	    	JceOpenSSLPKCS8DecryptorProviderBuilder jce = 
	        	new JceOpenSSLPKCS8DecryptorProviderBuilder();
	    	jce.setProvider(new BouncyCastleProvider());
	    	InputDecryptorProvider decProv = jce.build(password.toCharArray());
	    	keyInfo = ((PKCS8EncryptedPrivateKeyInfo)keyPair).decryptPrivateKeyInfo(decProv);
	    }
	    else if (keyPair instanceof PrivateKeyInfo){
	        keyInfo = (PrivateKeyInfo) keyPair;
	    }			
		privateKey = (RSAKeyParameters)PrivateKeyFactory.createKey(keyInfo);
		
		pemParser.close();
    	return privateKey;
	}
	
	public RSAKeyParameters getPublicKey(String certFile){
		RSAKeyParameters publicKey = null;
		try(FileReader reader = new FileReader(certFile);
			PEMParser pemParser = new PEMParser(reader)){
			X509CertificateHolder certificate;
			certificate = (X509CertificateHolder)pemParser.readObject();
			publicKey = (RSAKeyParameters)PublicKeyFactory.createKey(
										certificate.getSubjectPublicKeyInfo());
		}catch (IOException e) {
			System.out.println(e.getMessage());
		}
		return publicKey;
	}
	
	public String encryptString(RSAKeyParameters publicKey, String plainText) throws InvalidCipherTextException, UnsupportedEncodingException{
		String cipherText;
		cipherText = Base64.toBase64String(encryptBytes(publicKey, plainText.getBytes("UTF-8")));
		return cipherText;
	}
	
	public byte[] encryptBytes(RSAKeyParameters publicKey, byte[] plainBytes) throws InvalidCipherTextException{
		OAEPEncoding cipher = new OAEPEncoding(new RSAEngine());
		cipher.init(true, publicKey);
		return cipher.processBlock(plainBytes, 0, plainBytes.length);
	}
	
	public String decryptString(RSAKeyParameters privateKey, String cipherText) throws UnsupportedEncodingException, InvalidCipherTextException{
		byte [] cipherBytes = Base64.decode(cipherText);
		return new String(decryptBytes(privateKey, cipherBytes), "UTF-8");		
	}
	
	public byte[] decryptBytes(RSAKeyParameters privateKey, byte[] cipherBytes) throws InvalidCipherTextException {
		OAEPEncoding cipher = new OAEPEncoding(new RSAEngine());
		cipher.init(false, privateKey);
		return cipher.processBlock(cipherBytes, 0, cipherBytes.length);
	}
}
