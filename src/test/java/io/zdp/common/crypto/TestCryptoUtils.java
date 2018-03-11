package io.zdp.common.crypto;

import java.math.BigInteger;
import java.security.PublicKey;

import org.apache.commons.lang3.tuple.Pair;
import org.bitcoinj.core.Base58;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class TestCryptoUtils extends TestCase {

	public void test() throws Exception {

		BigInteger privateKey = CryptoUtils.generateECPrivateKey();
		System.out.println("Private: " + privateKey);
		String privateEncoded = Base58.encode(privateKey.toByteArray());
		System.out.println("Private b58: " + privateEncoded);

		assertNotNull(privateKey);

		byte[] publicKey = CryptoUtils.getPublicKeyFromPrivate(privateKey, true);

		System.out.println("Hex pub: " + Hex.toHexString(publicKey));
		System.out.println("B58 pub: " + Base58.encode(publicKey));

		BigInteger pubInt = new BigInteger(1, publicKey);

		System.out.println(pubInt);

		String accountId = CryptoUtils.generateAccountUuid(Hex.toHexString(publicKey));
		System.out.println("Account id: " + accountId);

		// address
		String addr = CryptoUtils.generateAccountUniqueAddress(Hex.toHexString(publicKey));
		System.out.println(addr);

	}

	public void testSign() throws Exception {

		String text = "hello world";

		Pair<String, String> account = CryptoUtils.getNewAccount();

		{
			byte[] signature = null;

			// sign
			{
				signature = CryptoUtils.sign(Base58.decode(account.getLeft()), text);
			}

			System.out.println("Sign: " + Hex.toHexString(signature));

			// verify
			{
				String pubToVerify = Hex.toHexString(Base58.decode(account.getRight()));
				PublicKey pk = CryptoUtils.getPublicKeyFromCompressedEncodedHexForm(pubToVerify);
				boolean valid = CryptoUtils.isValidSignature(pk, text, signature);
				System.out.println(valid);
				assertTrue(valid);
			}
		}

	}

}
