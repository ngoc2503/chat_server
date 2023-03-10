package util;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class AESUtil {
	protected static final String ALGORITHM = "AES";
	protected static final String SALT = "99552371f24b195043148eb3e59d9fe84eb7efea";
	protected static final int KEY_LENGTH = 256;
	protected static final int IV_LENGTH = 16;
	
	public AESUtil(){
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public SecretKey getSecretKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException{
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT.getBytes(), 65536, KEY_LENGTH);
		SecretKey tmp = factory.generateSecret(spec);
		
		return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
		
	}
	
	public byte[] encryptBytes(SecretKey key, byte[] plainBytes) throws GeneralSecurityException{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecureRandom random = new SecureRandom();
		byte[] iv = random.generateSeed(IV_LENGTH);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		
		int cipherLength = cipherBytes.length;
		
		byte[] out = new byte[IV_LENGTH + cipherLength];
		System.arraycopy(iv, 0, out, 0, IV_LENGTH);
		System.arraycopy(cipherBytes, 0, out, IV_LENGTH, cipherLength);
		
		return out;
	}
	
	public String encryptString(SecretKey key, String plainText) throws UnsupportedEncodingException, GeneralSecurityException{
		String cipherText;
		cipherText = Base64.toBase64String(encryptBytes(key, plainText.getBytes("UTF-8")));
		return cipherText;
	}
	
	public byte[] decryptBytes(SecretKey key, byte[] cipherBytes) throws GeneralSecurityException{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		byte[] iv = new byte[IV_LENGTH];
		System.arraycopy(cipherBytes, 0, iv, 0,  IV_LENGTH);
		int cipherLength = cipherBytes.length - IV_LENGTH;
		byte[] cipherData = new byte[cipherLength];
		System.arraycopy(cipherBytes, IV_LENGTH, cipherData, 0, cipherLength);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		return cipher.doFinal(cipherData);
	}
	
	public String decryptString(SecretKey key, String cipherText) throws UnsupportedEncodingException, GeneralSecurityException{
		byte[] cipherBytes = Base64.decode(cipherText);
		return new String(decryptBytes(key, cipherBytes), "UTF-8");
	}
}
