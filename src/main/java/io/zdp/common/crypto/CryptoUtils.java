package io.zdp.common.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.apache.commons.codec.digest.DigestUtils;

public class CryptoUtils {

	private static final String RSA = "RSA";

	public static String generateRandomNumber256bits() throws NoSuchAlgorithmException {

		final SecureRandom random = SecureRandom.getInstanceStrong();

		byte[] array = new byte[128];

		random.nextBytes(array);

		return DigestUtils.sha256Hex(array);

	}

	public static void main(String[] args) throws Exception {
		String seed = generateRandomNumber256bits();
		System.out.println(seed);
		System.out.println(seed.length());
	}

	public static boolean isValidAddress(String hash) {
		return hash != null && hash.trim().length() == 64;
	}

	public static byte[] encrypt(PrivateKey privateKey, byte[] message) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(message);
	}

	public static byte[] encrypt(PrivateKey privateKey, String message) throws Exception {
		return encrypt(privateKey, message.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] decrypt(PublicKey publicKey, byte[] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encrypted);
	}

	public static KeyPair generateKeys(final String seed) throws NoSuchAlgorithmException, NoSuchProviderException {

		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);

		final SecureRandom random = new SecureRandom(seed.getBytes(StandardCharsets.UTF_8));
		random.setSeed(new BigInteger(seed, 16).toByteArray());

		kpg.initialize(2048, random);

		final KeyPair keys = kpg.generateKeyPair();
		return keys;
	}

}
