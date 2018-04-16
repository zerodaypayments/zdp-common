package io.zdp.common.crypto;

import io.zdp.common.crypto.model.AccountKeys;
import junit.framework.TestCase;

public class TestCryptos extends TestCase {

	public void test() throws Exception {

		AccountKeys kp = Cryptos.getNewAccount();

		System.out.println("Private as hex: " + kp.getPrivateKeyAsHex());
		System.out.println("Private key:" + kp.getPrivateKey58());
		
		System.out.println("Public key:" + kp.getPublicKey58AsAddress());
		System.out.println("Public as hex: " + kp.getPublicKeyAsHex());

	}

}
