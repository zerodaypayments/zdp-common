package io.zdp.common.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import org.apache.commons.codec.digest.DigestUtils;
import org.bitcoinj.core.Base58;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.zdp.common.crypto.model.AccountKeys;

public class Cryptos {

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private static final String RIPEMD160 = "RIPEMD160";

	private static final String ECIES = "ECIES";

	private static final String SECP256K1 = "secp256k1";

	private static final String EC = "EC";

	private static final Logger log = LoggerFactory.getLogger(Cryptos.class);

	static {

		Security.addProvider(new BouncyCastleProvider());

	}

	/**
	 * Generate an EC private key
	 */
	private static BigInteger generateECPrivateKey() {

		try {

			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(SECP256K1);
			KeyPairGenerator g = KeyPairGenerator.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME);
			g.initialize(ecSpec, SECURE_RANDOM);
			KeyPair pair = g.generateKeyPair();

			BCECPrivateKey privKey = (BCECPrivateKey) pair.getPrivate();
			return privKey.getD();

		} catch (Exception e) {
			log.error("Error: ", e);
		}

		return null;

	}

	/**
	 * Returns public key bytes from the given private key. To convert a byte
	 * array into a BigInteger, use <tt>
	 * new BigInteger(1, bytes);</tt>
	 */
	public static byte[] getPublicKeyFromPrivate(BigInteger privKey) {
		ECPoint point = getPublicPointFromPrivate(privKey);
		return point.getEncoded(true);
	}

	/**
	 * Returns public key point from the given private key. To convert a byte
	 * array into a BigInteger, use <tt>
	 * new BigInteger(1, bytes);</tt>
	 */
	private static ECPoint getPublicPointFromPrivate(BigInteger privKey) {

		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(SECP256K1);

		if (privKey.bitLength() > ecSpec.getN().bitLength()) {
			privKey = privKey.mod(ecSpec.getN());
		}
		return new FixedPointCombMultiplier().multiply(ecSpec.getG(), privKey);
	}

	public static byte[] ripemd160(String v) {
		return ripemd160(v.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] ripemd160(byte[] v) {
		try {
			final MessageDigest messageDigest = MessageDigest.getInstance(RIPEMD160, BouncyCastleProvider.PROVIDER_NAME);
			final byte[] hash = messageDigest.digest(v);
			return hash;
		} catch (NoSuchAlgorithmException e) {
			log.error("Error: ", e);
		} catch (NoSuchProviderException e) {
			log.error("Error: ", e);
		}
		return null;
	}

	public static AccountKeys getNewAccount() {

		BigInteger priv = Cryptos.generateECPrivateKey();

		return new AccountKeys(priv);
	}

	public static String toPublicBase58(byte[] pub) {

		pub = DigestUtils.sha256(pub);
		
		pub = DigestUtils.sha256(pub);
		
		pub = ripemd160(pub);

		return Base58.encode(pub);

	}

	/**
	 * Returns public key bytes from the given private key. To convert a byte
	 * array into a BigInteger, use <tt>
	 * new BigInteger(1, bytes);</tt>
	 */
	public static String getPublicKey58FromPrivateKey58(String privKey58) {
		byte[] publicKey = getPublicKeyFromPrivate(new BigInteger(Base58.decode(privKey58)));
		return toPublicBase58(publicKey);

	}

}
