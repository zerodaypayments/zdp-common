package io.zdp.common.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.Base58;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
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
			networkAddressPublicKey = loadPublicKey(Base64.decodeBase64(pubKey64));
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static PublicKey getNetworkAddressPublicKey() {
		return networkAddressPublicKey;
	}

	/**
	 * Load PublicKey
	 */
	public static PublicKey loadPublicKey(byte[] key) throws Exception {
		final PublicKey pubKey = KeyFactory.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(key));
		return pubKey;
	}

	/**
	 * Load PrivateKey
	 */
	public static PrivateKey loadPrivateKey(byte[] key) throws Exception {
		final PrivateKey privKey = KeyFactory.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME).generatePrivate(new PKCS8EncodedKeySpec(key));
		return privKey;
	}

	public static PrivateKey getPrivateKeyFromECBigIntAndCurve(BigInteger s) {

		ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(BRAINPOOLP256T1);

		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(EC);
			return keyFactory.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Generate an EC private key
	 */
	public static BigInteger generateECPrivateKey() {

		try {

			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(BRAINPOOLP256T1);
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
	public static byte[] getPublicKeyFromPrivate(BigInteger privKey, boolean compressed) {
		ECPoint point = getPublicPointFromPrivate(privKey);
		return point.getEncoded(compressed);
	}

	/**
	 * Returns public key point from the given private key. To convert a byte
	 * array into a BigInteger, use <tt>
	 * new BigInteger(1, bytes);</tt>
	 */
	public static ECPoint getPublicPointFromPrivate(BigInteger privKey) {

		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(BRAINPOOLP256T1);

		if (privKey.bitLength() > ecSpec.getN().bitLength()) {
			privKey = privKey.mod(ecSpec.getN());
		}
		return new FixedPointCombMultiplier().multiply(ecSpec.getG(), privKey);
	}

	/**
	 * Generate account UUID from Public Key
	 */
	public static String generateAccountUuid(final String publicKeyB58) throws Exception {

		final byte[] hash = DigestUtils.sha256(DigestUtils.sha256(publicKeyB58));

		final byte[] hashedString = ripemd160(hash);

		final String account = Base58.encode(hashedString);

		return account;

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

	/**
	 * Generate a unique address for an account with a public key
	 */
	public static String generateAccountUniqueAddress(final String publicKey58) {

		try {

			String accountUuid = generateAccountUuid(publicKey58);

			final byte[] publicKeyBytes = accountUuid.getBytes(StandardCharsets.UTF_8);

			final Cipher c = Cipher.getInstance(ECIES, BouncyCastleProvider.PROVIDER_NAME);

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

	public static byte[] sign(byte[] privateKeyBytes, String data) throws Exception {

		PrivateKey privateKey = getPrivateKeyFromECBigIntAndCurve(new BigInteger(privateKeyBytes));

		return sign(privateKey, data);
	}

	public static byte[] sign(String privateKeyHex, String data) throws Exception {

		PrivateKey privateKey = getPrivateKeyFromECBigIntAndCurve(new BigInteger(privateKeyHex));

		return sign(privateKey, data);
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

	/**
	 * Decode a point on this curve which has been encoded using point
	 * compression (X9.62 s 4.2.1 and 4.2.2) or regular encoding.
	 * 
	 * @param curve
	 *            The elliptic curve.
	 * 
	 * @param encoded
	 *            The encoded point.
	 * 
	 * @return the decoded point.
	 * 
	 */
	public static ECPoint decodePoint(EllipticCurve curve, byte[] encoded) {
		ECCurve c = null;

		if (curve.getField() instanceof ECFieldFp) {
			c = new ECCurve.Fp(((ECFieldFp) curve.getField()).getP(), curve.getA(), curve.getB());
		} else {
			int k[] = ((ECFieldF2m) curve.getField()).getMidTermsOfReductionPolynomial();

			if (k.length == 3) {
				c = new ECCurve.F2m(((ECFieldF2m) curve.getField()).getM(), k[2], k[1], k[0], curve.getA(), curve.getB());
			} else {
				c = new ECCurve.F2m(((ECFieldF2m) curve.getField()).getM(), k[0], curve.getA(), curve.getB());
			}
		}

		return c.decodePoint(encoded);
	}

	public static PublicKey getPublicKeyFromRequest(String value) throws Exception {
		return CryptoUtils.getPublicKeyFromCompressedEncodedHexForm(Hex.toHexString(Base58.decode(value)));
	}

	public static PublicKey getPublicKeyFromCompressedEncodedHexForm(String hex) throws Exception {

		ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(CryptoUtils.BRAINPOOLP256T1);

		ECNamedCurveSpec params = new ECNamedCurveSpec(CryptoUtils.BRAINPOOLP256T1, ecParameterSpec.getCurve(), ecParameterSpec.getG(), ecParameterSpec.getN());

		ECPoint publicPoint = CryptoUtils.decodePoint(params.getCurve(), Hex.decode(hex));

		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(publicPoint, ecParameterSpec);

		KeyFactory keyFactory = KeyFactory.getInstance(CryptoUtils.EC);

		PublicKey pk = keyFactory.generatePublic(pubKeySpec);

		return pk;

	}

	public static boolean isValidAddress(String address) {
		return StringUtils.startsWith(address, ADDRESS_PREFIX_ZDP00) && StringUtils.length(address) == 160;
	}

}
