package io.zdp.common.crypto;

import java.math.BigInteger;
import java.security.PublicKey;

import org.bitcoinj.core.Base58;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class TestCryptoUtils extends TestCase {

	public void test() throws Exception {

		BigInteger privateKey = CryptoUtils.generateECPrivateKey();
		System.out.println("Private: " + privateKey);

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

		byte[] signature = null;

		// sign
		{
			String privToSign = "42914229365365066745332708095887935810489641559952468893285950129983775193557";
			signature = CryptoUtils.sign(CryptoUtils.getPrivateKeyFromECBigIntAndCurve(new BigInteger(privToSign)), text);
		}

		System.out.println("Sign: " + Hex.toHexString(signature));

		// verify
		{
			String pubToVerify = "0234b6f4003a61ca837e27cb2adc8cfa46a7881b58451c210bc56f7b81eadd22d7";

			PublicKey pk = CryptoUtils.getPublicKeyFromCompressedEncodedHexForm(pubToVerify);

			boolean valid = CryptoUtils.isValidSignature(pk, text, signature);

			System.out.println(valid);

			assertTrue(valid);

		}

	}

}
