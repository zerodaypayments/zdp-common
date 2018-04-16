package io.zdp.common.crypto;

import java.math.BigInteger;
import java.security.PublicKey;

import org.bitcoinj.core.Base58;
import org.bouncycastle.util.encoders.Hex;

import io.zdp.common.crypto.model.AccountKeys;
import junit.framework.TestCase;

public class TestCryptoUtils extends TestCase {

	public void test() throws Exception {

		AccountKeys kp = CryptoUtils.getNewAccount();

		System.out.println("pPRIV :" + kp.getPrivateKey58());
		System.out.println("ppub :" + kp.getPublicKey58AsAddress());

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

		String accountId = CryptoUtils.generateAccountUuidFromPublicKey58(Hex.toHexString(publicKey));
		System.out.println("Account id: " + accountId);

		// address
		String addr = CryptoUtils.generateUniqueAddressByPublicKey58(Hex.toHexString(publicKey));
		System.out.println(addr);

	}

	public void testPublicKeyFromPrivateKey() {

		String privKey58 = "iZM1d2wZCeD7489wEh14aipyHRM8y7oHYrYGmQvKBM2";
		String pub = CryptoUtils.getPublicKey58FromPrivateKey58(privKey58);

		assertEquals("etQ16UPTLz6RUSDF3AMmhFN42WFvg9Rm8apQ99zLamfH", pub);

	}

	public void testSign() throws Exception {

		String text = "hello world";

		AccountKeys account = CryptoUtils.getNewAccount();

		{
			byte[] signature = null;

			// sign
			{
				signature = CryptoUtils.sign(Base58.decode(account.getPrivateKey58()), text);
			}

			System.out.println("Sign: " + Hex.toHexString(signature));

			// verify
			{
				String pubToVerify = Hex.toHexString(Base58.decode(account.getPublicKey58AsAddress()));
				PublicKey pk = CryptoUtils.getPublicKeyFromCompressedEncodedHexForm(pubToVerify);
				boolean valid = CryptoUtils.isValidSignature(pk, text, signature);
				System.out.println(valid);
				assertTrue(valid);
			}
		}

	}

}
