package com.svlada.security.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * <p>Title: CipherUtils</p>
 * <p>Description: Utility class that helps encryptWithPublicKey and decryptWithPrivateKey strings using RSA algorithm</p>
 *
 * @author Aviran Mordo http://aviran.mordos.com
 * @version 1.0
 */
public class CipherUtils {


	public static final KeyUtil keyUtil = new KeyUtil();

	public CipherUtils() {

	}

	/**
	 * Init java security to add BouncyCastle as an RSA provider
	 */
	private static void init() {
		Security.addProvider(new BouncyCastleProvider());

	}

	public String sighnData(PrivateKey privateKey, String dataToSign, SignatureKeyAlgorithm.Algo algo) throws GeneralSecurityException {

		Signature signer = null;
		try {
			signer = Signature.getInstance(algo.getJcaName(), KeyUtil.provider);
			signer.initSign(privateKey);
			signer.update(Base64.decodeBase64(dataToSign) );
			return Base64.encodeBase64String( signer.sign() ) ;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
			throw new GeneralSecurityException("CipherUtils.sighnData", e.getCause());
		}



	}

	/**
	 * Encrypt a text using public key.
	 *
	 * @param text The original unencrypted text
	 * @param key  The public key
	 * @return Encrypted text
	 * @throws Exception
	 */
	private static byte[] encryptWithPublicKey(byte[] text, PublicKey key) throws Exception {
		byte[] cipherText = null;
		//
		// get an RSA cipher object and print the provider
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// encryptWithPublicKey the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text);
		return cipherText;
	}

	/**
	 * Encrypt a text using public key. The result is enctypted BASE64 encoded text
	 *
	 * @param text The original unencrypted text
	 * @param key  The public key
	 * @return Encrypted text encoded as BASE64
	 * @throws Exception
	 */
	public static String encryptWithPublicKey(String text, PublicKey key)  {

		try {
			byte[] cipherText = encryptWithPublicKey(text.getBytes("UTF8"), key);
			String encryptedText = Base64.encodeBase64String(cipherText);
			return encryptedText;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Decrypt text using private key
	 *
	 * @param text The encrypted text
	 * @param key  The private key
	 * @return The unencrypted text
	 * @throws Exception
	 */
	private static byte[] decryptWithPrivateKey(byte[] text, PrivateKey key) throws Exception {
		byte[] dectyptedText = null;
		// decryptWithPrivateKey the text using the private key
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		dectyptedText = cipher.doFinal(text);
		return dectyptedText;

	}

	/**
	 * Decrypt BASE64 encoded text using private key
	 *
	 * @param text The encrypted text, encoded as BASE64
	 * @param key  The private key
	 * @return The unencrypted text encoded as UTF8
	 * @throws Exception
	 */
	public static String decryptWithPrivateKey(String text, PrivateKey key)  {
		String result = null;
		// decryptWithPrivateKey the text using the private key
		byte[] dectyptedText = new byte[0];
		try {
			dectyptedText = decryptWithPrivateKey(Base64.decodeBase64(text), key);
			result = new String(dectyptedText, "UTF8");
		} catch (Exception e) {
			e.printStackTrace();
		}

		return result;

	}


	/**
	 * Encrypt file using 1024 RSA encryption
	 *
	 * @param srcFileName  Source file name
	 * @param destFileName Destination file name
	 * @param key          The key. For encryption this is the Private Key and for decryption this is the public key
	 * @throws Exception
	 */
	public static void encryptFile(String srcFileName, String destFileName, PublicKey key) throws Exception {
		encryptDecryptFile(srcFileName, destFileName, key, Cipher.ENCRYPT_MODE);
	}

	/**
	 * Decrypt file using 1024 RSA encryption
	 *
	 * @param srcFileName  Source file name
	 * @param destFileName Destination file name
	 * @param key          The key. For encryption this is the Private Key and for decryption this is the public key
	 * @throws Exception
	 */
	public static void decryptFile(String srcFileName, String destFileName, PrivateKey key) throws Exception {
		encryptDecryptFile(srcFileName, destFileName, key, Cipher.DECRYPT_MODE);
	}

	/**
	 * Encrypt and Decrypt files using 1024 RSA encryption
	 *
	 * @param srcFileName  Source file name
	 * @param destFileName Destination file name
	 * @param key          The key. For encryption this is the Private Key and for decryption this is the public key
	 * @param cipherMode   Cipher Mode
	 * @throws Exception
	 */
	public static void encryptDecryptFile(String srcFileName, String destFileName, Key key, int cipherMode) throws Exception {
		OutputStream outputWriter = null;
		InputStream inputReader = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			String textLine = null;
			//RSA encryption data size limitations are slightly less than the key modulus size,
			//depending on the actual padding scheme used (e.g. with 1024 bit (128 byte) RSA key,
			//the size limit is 117 bytes for PKCS#1 v 1.5 padding. (http://www.jensign.com/JavaScience/dotnet/RSAEncrypt/)
			byte[] buf = cipherMode == Cipher.ENCRYPT_MODE ? new byte[100] : new byte[128];
			int bufl;
			// init the Cipher object for Encryption...
			cipher.init(cipherMode, key);

			// start FileIO
			outputWriter = new FileOutputStream(destFileName);
			inputReader = new FileInputStream(srcFileName);
			while ((bufl = inputReader.read(buf)) != -1) {
				byte[] encText = null;
				if (cipherMode == Cipher.ENCRYPT_MODE) {
					encText = encryptWithPublicKey(copyBytes(buf, bufl), (PublicKey) key);
				} else {
					encText = decryptWithPrivateKey(copyBytes(buf, bufl), (PrivateKey) key);
				}
				outputWriter.write(encText);
			}
			outputWriter.flush();

		} finally {
			try {
				if (outputWriter != null) {
					outputWriter.close();
				}
				if (inputReader != null) {
					inputReader.close();
				}
			} catch (Exception e) {
				// do nothing...
			} // end of inner try, catch (Exception)...
		}
	}

	private static byte[] copyBytes(byte[] arr, int length) {
		byte[] newArr = null;
		if (arr.length == length) {
			newArr = arr;
		} else {
			newArr = new byte[length];
			for (int i = 0; i < length; i++) {
				newArr[i] = (byte) arr[i];
			}
		}
		return newArr;
	}

	/**
	 * Encode bytes array to BASE64 string
	 *
	 * @param bytes that should be encoded to string
	 * @return Encoded string
	 */
	private static String encodeBASE64(byte[] bytes) {
		return Base64.encodeBase64String(bytes);
	}

	/**
	 * Decode BASE64 encoded string to bytes array
	 *
	 * @param text The string that should be decoded to byte[]
	 * @return byte[]
	 */
	private static byte[] decodeBASE64(String text) throws IOException {
		return Base64.decodeBase64(text);
	}


// --------- encrypt and decrypt With SymmetricKey ---------

	public static String encryptWithSymmetricKey(String plaintext, Key symmetricKey) throws Exception {
		return encryptWithSymmetricKey(generateIV(), plaintext, symmetricKey);
	}

	public static String decryptWithSymmetricKey(String ciphertext, Key symmetricKey) throws Exception {
		String[] parts = ciphertext.split(":");
		byte[] iv = Base64.decodeBase64(parts[0]);
		byte[] encrypted = Base64.decodeBase64(parts[1]);
		byte[] decrypted = decryptWithSymmetricKey(iv, encrypted, symmetricKey);
		return new String(decrypted);
	}

	private static String encryptWithSymmetricKey(byte[] iv, String plaintext, Key symmetricKey) throws Exception {

		byte[] decrypted = plaintext.getBytes();
		byte[] encrypted = encryptWithSymmetricKey(iv, decrypted, symmetricKey);

		StringBuilder ciphertext = new StringBuilder();

		ciphertext.append(Base64.encodeBase64String(iv));
		ciphertext.append(":");
		ciphertext.append(Base64.encodeBase64String(encrypted));

		return ciphertext.toString();

	}


	private static byte[] generateIV() {
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		return iv;
	}


	private static byte[] encryptWithSymmetricKey(byte[] iv, byte[] plaintext, Key symmetricKey) throws Exception {
		Cipher cipher = Cipher.getInstance(symmetricKey.getAlgorithm() + "/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
		return cipher.doFinal(plaintext);
	}

	private static byte[] decryptWithSymmetricKey(byte[] iv, byte[] ciphertext, Key symmetricKey) throws Exception {
		Cipher cipher = Cipher.getInstance(symmetricKey.getAlgorithm() + "/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
		return cipher.doFinal(ciphertext);
	}








}
