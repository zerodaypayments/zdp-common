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
import java.security.Security;

import javax.crypto.Cipher;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

public class CryptoUtils {

	private static final String RSA = "RSA";
	private static final String BC = "BC";
	private static final String PBEWITHSHA256AND256BITAES_CBC_BC = "PBEWITHSHA256AND256BITAES-CBC-BC";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static String generateRandomNumber256bits() throws NoSuchAlgorithmException {

		final SecureRandom random = SecureRandom.getInstanceStrong();

		byte[] array = new byte[128];

		random.nextBytes(array);

		return DigestUtils.sha256Hex(array);

	}

	public static boolean isValidAddress(String hash) {
		if (StringUtils.isBlank(hash)) {
			return false;
		}

		try {
			Base58.decode(hash);
		} catch (AddressFormatException e) {
			return false;
		}
		return true;
	}

	public static byte[] encrypt(PrivateKey privateKey, byte[] message) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(message);
	}

	public static byte[] encrypt(PublicKey pubKey, byte[] message) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		return cipher.doFinal(message);
	}

	public static byte[] encrypt(PrivateKey privateKey, String message) throws Exception {
		return encrypt(privateKey, message.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] encrypt(PublicKey pubKey, String message) throws Exception {
		return encrypt(pubKey, message.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] decrypt(PublicKey publicKey, byte[] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encrypted);
	}

	public static byte[] decrypt(PrivateKey privKey, byte[] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		return cipher.doFinal(encrypted);
	}

	public static KeyPair generateKeys(final String seed) throws NoSuchAlgorithmException, NoSuchProviderException {

		final KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);

		final SecureRandom random = new SecureRandom(seed.getBytes(StandardCharsets.UTF_8));
		random.setSeed(new BigInteger(seed, 16).toByteArray());

		kpg.initialize(4096, random);

		final KeyPair keys = kpg.generateKeyPair();
		return keys;
	}

	public static byte[] encryptLargeData(String password, byte[] data) throws Exception {

		StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
		encryptor.setPassword(password);
		encryptor.setAlgorithm(PBEWITHSHA256AND256BITAES_CBC_BC);
		byte[] encryptedBytes = encryptor.encrypt(data);

		return encryptedBytes;

	}

	public static byte[] decryptLargeData(String password, byte[] data) throws Exception {

		StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
		encryptor.setPassword(password);
		encryptor.setAlgorithm(PBEWITHSHA256AND256BITAES_CBC_BC);
		byte[] decryptedBytes = encryptor.decrypt(data);

		return decryptedBytes;

	}
	
	public String generateAddress(String balanceUuid) {
		// TODO
		return null;
	}

}
