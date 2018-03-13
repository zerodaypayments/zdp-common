package io.zdp.common.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.Base58;
import org.bouncycastle.util.encoders.Hex;

/**
 * Based on https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * 
 * @author sn_1970@yahoo.com
 *
 */
public class Mnemonics {

	static final int wordsLengthBit = 11;

	public static enum Language {
		CHINESE_SIMPLIFIED, //
		CHINESE_TRADITIONAL, //
		ENGLISH, //
		FRENCH, //
		ITALIAN, //
		JAPANESE, //
		KOREAN, //
		SPANISH //
	}

	//private final Logger log = LoggerFactory.getLogger(this.getClass());

	private static final Map<Language, List<String>> WORDS = new HashMap<>();

	static {
		try {
			WORDS.put(Language.CHINESE_SIMPLIFIED, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/chinese_simplified.txt"), StandardCharsets.UTF_8));
			WORDS.put(Language.CHINESE_TRADITIONAL, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/chinese_traditional.txt"), StandardCharsets.UTF_8));
			WORDS.put(Language.ENGLISH, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/english.txt"), StandardCharsets.UTF_8));
			WORDS.put(Language.FRENCH, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/french.txt"), StandardCharsets.UTF_8));
			WORDS.put(Language.ITALIAN, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/italian.txt"), StandardCharsets.UTF_8));
			WORDS.put(Language.JAPANESE, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/japanese.txt"), StandardCharsets.UTF_8));
			WORDS.put(Language.KOREAN, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/korean.txt"), StandardCharsets.UTF_8));
			WORDS.put(Language.SPANISH, IOUtils.readLines(Mnemonics.class.getResourceAsStream("/wordlist/spanish.txt"), StandardCharsets.UTF_8));
		} catch (Exception e) {
			//log.error("Error: ", e);
			e.printStackTrace();
		}
	}

	public static List<String> generateWords(final Language lang, byte[] privateKey) {

		final List<String> words = new ArrayList<>();

		final String seedHash = DigestUtils.sha256Hex(privateKey);

		BigInteger number = new BigInteger(privateKey);
		String binaryString = number.toString(2);

		if (binaryString.length() != 256) {
			binaryString = StringUtils.leftPad(binaryString, 256, "0");
		}

		BigInteger numberChecksumBigInteger = new BigInteger(seedHash.toString(), 16);

		String numberChecksumBinary = numberChecksumBigInteger.toString(2);

		String hash = numberChecksumBinary.substring(0, 8);
		binaryString = binaryString + hash;

		for (int i = 0; i < binaryString.length(); i += wordsLengthBit) {
			String sub = binaryString.substring(i, i + wordsLengthBit);
			int wordIndex = Integer.parseInt(sub, 2);
			words.add(WORDS.get(lang).get(wordIndex));
		}

		return words;

	}

	public static byte[] generateSeedFromWords(final Language lang, List<String> words) {

		StringBuilder sb = new StringBuilder();
		for (String word : words) {
			int index = WORDS.get(lang).indexOf(word);
			String bin = Integer.toString(index, 2);
			bin = StringUtils.leftPad(bin, wordsLengthBit, '0');
			sb.append(bin);
		}

		// remove last 8 bits
		sb.setLength(sb.length() - 8);

		BigInteger i = new BigInteger(sb.toString(), 2);

		return i.toByteArray();
	}

}
