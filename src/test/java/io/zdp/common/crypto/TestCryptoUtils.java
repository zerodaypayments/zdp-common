package io.zdp.common.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import org.junit.Test;

import junit.framework.TestCase;

public class TestCryptoUtils extends TestCase {

	@Test
	public void testGenerateKeys() {

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

		} catch (Exception e) {
			fail(e.getMessage());
		}

	}

	@Test
	public void testEncryption() {

		String uuid = UUID.randomUUID().toString();

		char[] pass = "pass123".toCharArray();

		String encrypted = CryptoUtils.encrypt(uuid, pass);

		assertNotNull(encrypted);

		assertFalse(encrypted.equals(uuid));

		String decrypted = CryptoUtils.decrypt(encrypted, pass);

		assertEquals(uuid, decrypted);

	}

}
