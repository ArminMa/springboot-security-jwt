package com.svlada.security.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Created by Sys on 2016-07-22.
 */
public class KeyUtil {

	protected static final String RSA_ALGORITHM = "RSA";
	protected static final String AES_ALGORITHM = "AES";
	public final static Provider provider = new BouncyCastleProvider();
	public static SignatureKeyAlgorithm sigKeyAlgo = new SignatureKeyAlgorithm();
//	protected static final String HMACSHA1 = "HmacSHA1";

//	SecureRandom secureRandom = JCAUtil.getSecureRandom();

	public KeyUtil() {
		init();
	}

	/**
	 * Init java security to add BouncyCastle as an RSA provider
	 */
	private static void init() {

		SignatureKeyAlgorithm.enableBouncyCastle();
	}

	// ---------||||||||||||||||| generate Key util |||||||||||||||||---------

	public static class SymmetricKey {

		/**
		 *
		 * @param Bytes where 16 Bytes is (16bytes*8bits) = 128bits, 32 Bytes = 256 bits
		 * @return SecretKey instanse
		 */
		public static SecretKey generateSecretAesKey(int Bytes)   {
			return new SecretKeySpec(SecureRandom.getSeed(Bytes), "AES");
		}

		/**
		 *
		 *  Bytes where 16 Bytes is (16bytes*8bits) = 128bits, 32 Bytes = 256 bits
		 * @return SecretKey instance
		 */
		public static SecretKey generateSecretKey(int byteSize, SignatureKeyAlgorithm.Algo algo)   {
			return new SecretKeySpec(SecureRandom.getSeed(byteSize), algo.getJcaName());

		}

		/**
		 *
		 * @param algo the algorithm for the key -> AES
		 * @param bits bits 128 / 248
		 * @return SecretKey
		 */
		private static SecretKey generateSymmetricKey(String algo, int bits) throws GeneralSecurityException {

			SecureRandom secureRandom = new SecureRandom();
			secureRandom.setSeed(System.nanoTime());
			KeyGenerator generator = KeyGenerator.getInstance(algo);
			generator.init(bits, secureRandom);
			return generator.generateKey();

		}


		/**
		 * Convert a SecretKey to string encoded as BASE64
		 *
		 * @param key The key (private or public)
		 * @return A string representation of the key
		 */
		public static String getKeyAsString(SecretKey key) {
			// Get the bytes of the key
			byte[] keyBytes = key.getEncoded();
			return Base64.encodeBase64String(keyBytes);
		}

		/**
		 *
		 * @param key is encode Base64 String
		 * @return SecretKey
		 */
		public static SecretKey getSecretKeyFromString(String key)  {
			byte[] decodedKey =  Base64.decodeBase64(key);
			return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		}


	}



//	public static SecretKey generateSymmetricHmacSha1Key() {
//		return generateSymmetricKey(HMACSHA1);
//	}



	public static SecretKey getSecretKeyFromString(String key) {

		byte[] decodedKey = decodeBASE64(key);
		return new SecretKeySpec(decodedKey, "AES");
	}


	/**
	 * Generates Private Key from BASE64 encoded string
	 *
	 * @param key BASE64 encoded string which represents the key
	 * @return The PrivateKey
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKeyFromString(String key) throws GeneralSecurityException {

		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(key));
		return keyFactory.generatePrivate(privateKeySpec);


	}


	public static PrivateKey getPrivateKeyFromString(String key, String algo) throws GeneralSecurityException {

		KeyFactory keyFactory = KeyFactory.getInstance(algo);
		EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodeBASE64(key));
		return keyFactory.generatePrivate(privateKeySpec);



	}


	/**
	 * Generates Public Key from BASE64 encoded string
	 *
	 * @param key BASE64 encoded string which represents the key
	 * @return The PublicKey
	 * @throws Exception
	 */
	public static PublicKey getPublicKeyFromString(String key) throws GeneralSecurityException {

		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodeBASE64(key));
		KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
		return keyFactory.generatePublic(publicKeySpec);


	}

	public static PublicKey getPublicKeyFromString(String key, String algo) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance(algo);
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodeBASE64(key));
		return keyFactory.generatePublic(publicKeySpec);
	}


	/**
	 * Generate key which contains a pair of privae and public key using 1024 bytes
	 *
	 * @return key pair
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKeyPair() throws GeneralSecurityException {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
		keyGen.initialize(1024);
		return keyGen.generateKeyPair();

	}


	/**
	 * Encode bytes array to BASE64 string
	 *
	 * @param bytes
	 * @return Encoded string
	 */
	private static String encodeBASE64(byte[] bytes) {
		// BASE64Encoder b64 = new BASE64Encoder();
		// return b64.encode(bytes, false);
		return Base64.encodeBase64String(bytes);
	}

	/**
	 * Decode BASE64 encoded string to bytes array
	 *
	 * @param text The string
	 * @return Bytes array
	 * @throws IOException
	 */
	private static byte[] decodeBASE64(String text)  {
		// BASE64Decoder b64 = new BASE64Decoder();
		// return b64.decodeBuffer(text);
		return Base64.decodeBase64(text);
	}



	/**
	 * Convert a Key to string encoded as BASE64
	 *
	 * @param key The key (private or public)
	 * @return A string representation of the key
	 */
	public static String getKeyAsString(Key key) {
		// Get the bytes of the key
		byte[] keyBytes = key.getEncoded();
		return encodeBASE64(keyBytes);
	}








}
