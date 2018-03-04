package io.zdp.common.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.bitcoinj.core.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoUtils {

	private static final String SHA256WITH_ECDSA = "SHA256withECDSA";

	public static final SecureRandom SECURE_RANDOM = new SecureRandom();

	public static final String RIPEMD160 = "RIPEMD160";

	public static final String ECIES = "ECIES";

	public static final String BRAINPOOLP256T1 = "brainpoolp256t1";

	public static final String EC = "EC";

	private static final Logger log = LoggerFactory.getLogger(CryptoUtils.class);

	public static final String ADDRESS_PREFIX_ZDP00 = "zdp00";

	private static PublicKey networkAddressPublicKey;

	static {

		Security.addProvider(new BouncyCastleProvider());

		try {
			String pubKey64 = IOUtils.toString(CryptoUtils.class.getResource("/cert/ec-public"), StandardCharsets.UTF_8);
			networkAddressPublicKey = generatePublicKey(Base64.decodeBase64(pubKey64));
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static PublicKey getNetworkAddressPublicKey() {
		return networkAddressPublicKey;
	}

	/**
	 * Generate a random EC key pair
	 */
	public static KeyPair generateECKeyPair() {

		try {

			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(BRAINPOOLP256T1);
			KeyPairGenerator g = KeyPairGenerator.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME);
			g.initialize(ecSpec, SECURE_RANDOM);
			KeyPair pair = g.generateKeyPair();

			return pair;

		} catch (Exception e) {
			log.error("Error: ", e);
		}

		return null;

	}

	/**
	 * Generate an ECC private key a HEX string 
	 */
	public static PrivateKey generateECKeyPairFromPrivateKey(String privateKeyHex) {

		try {

			KeyFactory kf = KeyFactory.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME);
			PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Hex.decode(privateKeyHex)));

			return privateKey;

		} catch (Exception e) {
			log.error("Error: ", e);
		}

		return null;

	}

	/**
	 * Generate account UUID from Public Key
	 */
	public static String generateAccountUuid(final String publicKeyHexString) throws Exception {

		final byte[] pub = Hex.decode(publicKeyHexString);

		final byte[] hash = DigestUtils.sha256(DigestUtils.sha256(pub));

		final MessageDigest messageDigest = MessageDigest.getInstance(RIPEMD160, BouncyCastleProvider.PROVIDER_NAME);

		final byte[] hashedString = messageDigest.digest(hash);

		final String account = Base58.encode(hashedString);

		return account;
	}

	/**
	 * Create PrivateKey from byte array
	 */
	public static PrivateKey generatePrivateKey(byte[] key) throws Exception {

		final PrivateKey privKey = KeyFactory.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME).generatePrivate(new PKCS8EncodedKeySpec(key));

		return privKey;

	}

	/**
	 * Create PublicKey from byte array
	 */
	public static PublicKey generatePublicKey(byte[] key) throws Exception {
		final PublicKey pubKey = KeyFactory.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(key));
		return pubKey;
	}

	/**
	 * Generate a unique address for an account with a public key
	 */
	public static String generateAccountUniqueAddress(final String publicKeyHexString) {

		try {

			String accountUuid = generateAccountUuid(publicKeyHexString);

			final byte[] publicKeyBytes = accountUuid.getBytes(StandardCharsets.UTF_8);

			final Cipher c = Cipher.getInstance(ECIES);

			c.init(Cipher.ENCRYPT_MODE, networkAddressPublicKey, SECURE_RANDOM);

			byte[] out = c.doFinal(publicKeyBytes);

			String address = Base58.encode(out);

			return ADDRESS_PREFIX_ZDP00 + address;
			
		} catch (Exception e) {
			log.error("Error: ", e);
			e.printStackTrace();
		}

		return null;

	}

	/**
	 * Sign a UTF-8 string by using a provided RSA private key
	 */
	public static byte[] sign(PrivateKey pvt, String data) throws Exception {

		Signature sign = Signature.getInstance(SHA256WITH_ECDSA, BouncyCastleProvider.PROVIDER_NAME);

		sign.initSign(pvt);

		sign.update(data.getBytes(StandardCharsets.UTF_8));

		return sign.sign();

	}

	/**
	 * Check is a Digital signature is valid by using provided RS public key
	 */
	public static boolean isValidSignature(PublicKey pub, String data, byte[] signature) throws Exception {

		try {

			Signature sign = Signature.getInstance(SHA256WITH_ECDSA, BouncyCastleProvider.PROVIDER_NAME);

			sign.initVerify(pub);

			sign.update(data.getBytes(StandardCharsets.UTF_8));

			return sign.verify(signature);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;

	}

}
