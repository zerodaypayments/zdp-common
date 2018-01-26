package io.zdp.common.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

import junit.framework.TestCase;

public class TestSigner extends TestCase {

	@Test
	public void testKeys() {

		try {

			String key = CryptoUtils.generateRandomNumber(256);

			assertNotNull(key);
			assertEquals(64, key.length());

			KeyPair keys = CryptoUtils.generateKeys(key);

			assertNotNull(keys);

			PublicKey pub = keys.getPublic();

			assertNotNull(pub);
			assertNotNull(pub.getAlgorithm());
			assertNotNull(pub.getFormat());
			assertNotNull(pub.getEncoded());
			assertTrue(pub.getEncoded().length > 0);

			PrivateKey priv = keys.getPrivate();

			assertNotNull(priv);
			assertNotNull(priv.getAlgorithm());
			assertNotNull(priv.getFormat());
			assertNotNull(priv.getEncoded());
			assertTrue(priv.getEncoded().length > 0);

			PrivateKey priv2 = Signer.generatePrivateKey(priv.getEncoded());
			assertEquals(priv.getAlgorithm(), priv2.getAlgorithm());
			assertEquals(priv.getFormat(), priv2.getFormat());

			PublicKey pub2 = Signer.generatePublicKey(pub.getEncoded());
			assertEquals(pub.getAlgorithm(), pub2.getAlgorithm());
			assertEquals(pub.getFormat(), pub2.getFormat());

		} catch (Exception e) {
			fail(e.getMessage());
		}

	}

	@Test
	public void testSigner() {

		try {

			String key = CryptoUtils.generateRandomNumber(256);

			assertNotNull(key);
			assertEquals(64, key.length());

			KeyPair keys = CryptoUtils.generateKeys(key);

			String data = "test data";

			byte[] signature = Signer.sign(keys.getPrivate(), data);

			assertNotNull(signature);
			assertTrue(signature.length > 0);

			assertTrue(Signer.isValidSignature(keys.getPublic(), data, signature));

			assertFalse(Signer.isValidSignature(keys.getPublic(), "xxxxx", signature));

		} catch (Exception e) {
			fail(e.getMessage());
		}

	}
}
