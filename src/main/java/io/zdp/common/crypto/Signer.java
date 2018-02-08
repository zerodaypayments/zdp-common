package io.zdp.common.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * Digital signature utility methods
 * 
 * @author sn_1970@yahoo.com
 *
 */
public class Signer {

	private static final String SHA256WITH_RSA = "SHA256withRSA";
	private static final String RSA = "RSA";

	/**
	 * Sign a UTF-8 string by using a provided RSA private key
	 */
	public static byte[] sign(PrivateKey pvt, String data) throws Exception {

		Signature sign = Signature.getInstance(SHA256WITH_RSA);

		sign.initSign(pvt);

		sign.update(data.getBytes(StandardCharsets.UTF_8));

		return sign.sign();

	}

	/**
	 * Check is a Digital signature is valid by using provided RS public key
	 */
	public static boolean isValidSignature(PublicKey pub, String data, String signature) throws Exception {

		Signature sign = Signature.getInstance(SHA256WITH_RSA);

		sign.initVerify(pub);

		sign.update(data.getBytes(StandardCharsets.UTF_8));

		return sign.verify(signature.getBytes(StandardCharsets.UTF_8));

	}

	/**
	 * Check is a Digital signature is valid by using provided RS public key
	 */
	public static boolean isValidSignature(PublicKey pub, String data, byte[] signature) throws Exception {

		Signature sign = Signature.getInstance(SHA256WITH_RSA);

		sign.initVerify(pub);

		sign.update(data.getBytes(StandardCharsets.UTF_8));

		return sign.verify(signature);

	}

	/**
	 * Create PrivateKey from byte array
	 */
	public static PrivateKey generatePrivateKey(byte[] key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		final PrivateKey privKey = KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(key));
		return privKey;
	}

	/**
	 * Create PublicKey from byte array
	 */
	public static PublicKey generatePublicKey(byte[] key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		final PublicKey pubKey = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(key));
		return pubKey;
	}

	public static String getPublicKeyHash(final PublicKey pubKey) {
		return getPublicKeyHash(pubKey.getEncoded());
	}

	public static String getPublicKeyHash(final byte[] pubKey) {
		byte[] addressHash = DigestUtils.sha512(pubKey);
		final String hash = DigestUtils.sha256Hex(addressHash);
		return hash;
	}

}
