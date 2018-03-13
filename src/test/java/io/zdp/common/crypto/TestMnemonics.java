package io.zdp.common.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.bitcoinj.core.Base58;
import org.junit.Test;

import io.zdp.common.utils.Mnemonics;
import io.zdp.common.utils.Mnemonics.Language;
import junit.framework.TestCase;

public class TestMnemonics extends TestCase {

	@Test
	public void test() throws NoSuchAlgorithmException {

		System.out.println("TestMnemonics.Test");

		for (int i = 0; i < 10000; i++) {
			Pair<String, String> newAccount = CryptoUtils.getNewAccount();

			String priv = newAccount.getLeft();

			System.out.println(priv);

			List<String> words = Mnemonics.generateWords(Language.ENGLISH, Base58.decode(priv));

			System.out.println(words);

			byte[] seed = Mnemonics.generateSeedFromWords(Language.ENGLISH, words);

			String seed58 = Base58.encode(seed);
			System.out.println(seed58);

			assertEquals(priv, seed58);
		}

	}

}
