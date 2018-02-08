package io.zdp.common.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

public class CryptoUtils {

	private static final String ZDP0 = "zdp0";
	private static final String RSA = "RSA";
	private static final String BC = "BC";
	private static final String PBEWITHSHA256AND256BITAES_CBC_BC = "PBEWITHSHA256AND256BITAES-CBC-BC";

	private static PublicKey publicKey;

	static {

		Security.addProvider(new BouncyCastleProvider());

		try {
			publicKey = Signer.generatePublicKey(IOUtils.toByteArray(CryptoUtils.class.getResource("/cert/public")));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
		}

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

		if (false == hash.startsWith(CryptoUtils.ZDP0)) {
			return false;
		}

		try {

			hash = StringUtils.removeStart(hash, ZDP0);

			Base58.decode(hash);

		} catch (AddressFormatException e) {
			return false;
		}

		return true;
	}

	public static byte[] encrypt(Key key, byte[] message) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(message);
	}

	public static byte[] encrypt(Key key, String message) throws Exception {
		return encrypt(key, message.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] decrypt(Key privKey, byte[] encrypted) throws Exception {
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

	public static String getUniqueAddressForAccountUuid(String balanceUuid) throws Exception {

		byte[] encrypted = CryptoUtils.encrypt(publicKey, balanceUuid);

		String address = Base58.encode(encrypted);

		address = ZDP0 + address;

		return address;
	}

	public static String getAccountUuidForUniqueAddress(PrivateKey privKey, String address) throws Exception {

		if (false == address.startsWith(ZDP0)) {
			throw new IllegalArgumentException("Address not valid, must start with '" + ZDP0 + "': " + address);
		}

		address = StringUtils.removeStart(address, ZDP0);

		byte[] encrypted = Base58.decode(address);

		byte[] decrypted = CryptoUtils.decrypt(privKey, encrypted);

		return new String(decrypted, StandardCharsets.UTF_8);
	}

}
