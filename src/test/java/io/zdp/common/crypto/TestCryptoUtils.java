package io.zdp.common.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import java.util.UUID;

import org.apache.commons.codec.digest.DigestUtils;
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
	public void testEncryption() throws Exception {

		String uuid = UUID.randomUUID().toString();

		String seed = DigestUtils.sha256Hex("pass123");
		KeyPair keys = CryptoUtils.generateKeys(seed);

		byte[] encrypted = CryptoUtils.encrypt(keys.getPrivate(), uuid);

		assertNotNull(encrypted);

		assertFalse(Objects.deepEquals(encrypted, uuid.getBytes(StandardCharsets.UTF_8)));

		byte[] decrypted = CryptoUtils.decrypt(keys.getPublic(), encrypted);

		assertTrue(Objects.deepEquals(uuid.getBytes(StandardCharsets.UTF_8), decrypted));

	}

}
