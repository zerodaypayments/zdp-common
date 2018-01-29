package io.zdp.common.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

public class CryptoUtils {

	private static final String RSA = "RSA";
	private static final String BC = "BC";
	private static final String PBEWITHSHA256AND256BITAES_CBC_BC = "PBEWITHSHA256AND256BITAES-CBC-BC";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static String generateRandomNumber(final int binaryDigits) throws NoSuchAlgorithmException {

		final StringBuilder sb = new StringBuilder();

		final SecureRandom random = SecureRandom.getInstanceStrong();

		// TODO change to SecureRandom.nextBytes
		for (int i = 0; i < binaryDigits / 4; i++) {
			sb.append(Integer.toHexString(random.nextInt(16)));
		}

		return sb.toString().toUpperCase();

	}

	public static boolean isValidAddress(String hash) {
		return hash != null && hash.trim().length() == 44;
	}

	public static String encrypt(String text, char[] password) {

		StandardPBEStringEncryptor mySecondEncryptor = new StandardPBEStringEncryptor();
		mySecondEncryptor.setProviderName(BC);
		mySecondEncryptor.setAlgorithm(PBEWITHSHA256AND256BITAES_CBC_BC);
		mySecondEncryptor.setPasswordCharArray(password);

		String enc = mySecondEncryptor.encrypt(text);

		return enc;
	}

	public static String decrypt(String text, char[] password) {

		StandardPBEStringEncryptor mySecondEncryptor = new StandardPBEStringEncryptor();
		mySecondEncryptor.setProviderName(BC);
		mySecondEncryptor.setAlgorithm(PBEWITHSHA256AND256BITAES_CBC_BC);
		mySecondEncryptor.setPasswordCharArray(password);

		String dec = mySecondEncryptor.decrypt(text);

		return dec;
	}

	public static KeyPair generateKeys(final String seed) throws NoSuchAlgorithmException, NoSuchProviderException {

		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA, BC);

		final SecureRandom random = new SecureRandom(seed.getBytes(StandardCharsets.UTF_8));
		random.setSeed(new BigInteger(seed, 16).toByteArray());

		kpg.initialize(2048, random);

		final KeyPair keys = kpg.generateKeyPair();
		return keys;
	}

}
