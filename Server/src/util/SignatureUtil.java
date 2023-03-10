package util;

import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
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

public class SignatureUtil {
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
	
	public RSAKeyParameters getPublicKey(String certFile)throws IOException {
		RSAKeyParameters publicKey = null;
		FileReader reader = new FileReader(certFile);
		PEMParser pemParser = new PEMParser(reader);
		X509CertificateHolder certificate;
		certificate = (X509CertificateHolder)pemParser.readObject();
		publicKey = (RSAKeyParameters)PublicKeyFactory.createKey(
										certificate.getSubjectPublicKeyInfo());
		pemParser.close();
		return publicKey;
	}
	
	public byte[] signBytes(RSAKeyParameters key, byte inputBytes[]) throws DataLengthException, CryptoException{
		RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
		signer.init(true, key);
		signer.update(inputBytes, 0, inputBytes.length);
		return signer.generateSignature();
	}
	
	public String signString(RSAKeyParameters key, String input) throws DataLengthException, CryptoException, UnsupportedEncodingException{
		byte[] inputBytes = input.getBytes("UTF-8");
		byte[] outputBytes = signBytes(key, inputBytes);
		return Base64.toBase64String(outputBytes);
	}
	
	public boolean verifyBytes(RSAKeyParameters key, byte inputBytes[], byte[] signature){
		RSADigestSigner verifier = new RSADigestSigner(new SHA256Digest());
		verifier.init(false, key);
		verifier.update(inputBytes, 0, inputBytes.length);
		return verifier.verifySignature(signature);
	}
	
	public boolean verifyString(RSAKeyParameters key, String input, String signature) throws UnsupportedEncodingException{
		byte[] inputBytes = input.getBytes("UTF-8");
		byte[] sigBytes = Base64.decode(signature);
		return verifyBytes(key, inputBytes,sigBytes);
	}
	
}

