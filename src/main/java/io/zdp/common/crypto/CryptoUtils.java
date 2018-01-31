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

public class CryptoUtils {

	private static final String RSA = "RSA";

	public static String generateRandomNumber(final int bits) throws NoSuchAlgorithmException {

		final StringBuilder sb = new StringBuilder();

		final SecureRandom random = SecureRandom.getInstanceStrong();

		// TODO change to SecureRandom.nextBytes
		for (int i = 0; i < bits / 4; i++) {
			sb.append(Integer.toHexString(random.nextInt(16)));
		}

		return sb.toString().toUpperCase();

	}

	public static void main(String[] args) throws Exception {
		String seed = generateRandomNumber(256);
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
