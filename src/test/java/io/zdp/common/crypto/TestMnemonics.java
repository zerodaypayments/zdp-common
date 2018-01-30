package io.zdp.common.crypto;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Test;

import io.zdp.common.utils.Mnemonics;
import io.zdp.common.utils.Mnemonics.Language;
import junit.framework.TestCase;

public class TestMnemonics extends TestCase {

	@Test
	public void testTo() throws NoSuchAlgorithmException {

		{
			String walletSeed = "80D0A7DB66CF849B6AC8C2A2B698B3C6AFD11A911DB22E8C0BF79720EF5F05C1";
			List<String> words = Mnemonics.generateWords(Language.ENGLISH, walletSeed);
			System.out.println(words);
			assertEquals("[liar, lunch, walnut, snow, weapon, ethics, private, blue, pencil, regular, coconut, minute, wonder, minute, dutch, rent, company, gate, worth, comic, auction, question, blade, disease]", words.toString());
		}

		{
			String walletSeed = "0000000000000000000000000000000000000000000000000000000000000000";
			List<String> words = Mnemonics.generateWords(Language.ENGLISH, walletSeed);
			System.out.println(words);
			assertEquals("[abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, blouse]", words.toString());
		}

		{
			String walletSeed = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";
			List<String> words = Mnemonics.generateWords(Language.ENGLISH, walletSeed);
			System.out.println(words);
			assertEquals("[legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, year, wave, sausage, worth, voyage]", words.toString());
		}

		{
			String walletSeed = "8080808080808080808080808080808080808080808080808080808080808080";
			List<String> words = Mnemonics.generateWords(Language.ENGLISH, walletSeed);
			System.out.println(words);
			assertEquals("[letter, advice, cage, absurd, amount, doctor, acoustic, avoid, letter, advice, cage, absurd, amount, doctor, acoustic, avoid, letter, advice, cage, absurd, amount, doctor, acoustic, brother]", words.toString());
		}

		{
			String walletSeed = "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c";
			List<String> words = Mnemonics.generateWords(Language.ENGLISH, walletSeed);
			System.out.println(words);
			assertEquals("[hamster, diagram, private, dutch, cause, delay, private, meat, slide, toddler, razor, book, happy, fancy, gospel, tennis, maple, dilemma, loan, word, shrug, inflict, delay, opera]", words.toString());
		}

		{
			String walletSeed = "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad";
			List<String> words = Mnemonics.generateWords(Language.ENGLISH, walletSeed);
			System.out.println(words);
			assertEquals("[all, hour, make, first, leader, extend, hole, alien, behind, guard, gospel, lava, path, output, census, museum, junior, mass, reopen, famous, sing, advance, salt, runway]", words.toString());
		}

		{
			String walletSeed = "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f";
			List<String> words = Mnemonics.generateWords(Language.ENGLISH, walletSeed);
			System.out.println(words);
			assertEquals("[void, come, effort, suffer, camp, survey, warrior, heavy, shoot, primary, clutch, crush, open, amazing, screen, patrol, group, space, point, ten, exist, slush, involve, young]", words.toString());
		}

	}

	@Test
	public void testFrom() throws NoSuchAlgorithmException {

		{
			String str = "abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, blouse";
			List<String> list = Arrays.stream(str.split(",")).map(String::trim).collect(Collectors.toList());
			String seed = Mnemonics.generateSeedFromWords(Language.ENGLISH, list);
			assertEquals("0000000000000000000000000000000000000000000000000000000000000000", seed);
		}

		{
			String str = "liar, lunch, walnut, snow, weapon, ethics, private, blue, pencil, regular, coconut, minute, wonder, minute, dutch, rent, company, gate, worth, comic, auction, question, blade, disease";
			List<String> list = Arrays.stream(str.split(",")).map(String::trim).collect(Collectors.toList());
			String seed = Mnemonics.generateSeedFromWords(Language.ENGLISH, list);
			assertEquals("80D0A7DB66CF849B6AC8C2A2B698B3C6AFD11A911DB22E8C0BF79720EF5F05C1", seed.toUpperCase());
		}

		{
			String str = "legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, year, wave, sausage, worth, voyage";
			List<String> list = Arrays.stream(str.split(",")).map(String::trim).collect(Collectors.toList());
			String seed = Mnemonics.generateSeedFromWords(Language.ENGLISH, list);
			assertEquals("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f".toUpperCase(), seed.toUpperCase());
		}

		{
			String str = "letter, advice, cage, absurd, amount, doctor, acoustic, avoid, letter, advice, cage, absurd, amount, doctor, acoustic, avoid, letter, advice, cage, absurd, amount, doctor, acoustic, brother";
			List<String> list = Arrays.stream(str.split(",")).map(String::trim).collect(Collectors.toList());
			String seed = Mnemonics.generateSeedFromWords(Language.ENGLISH, list);
			assertEquals("8080808080808080808080808080808080808080808080808080808080808080".toUpperCase(), seed.toUpperCase());
		}

		{
			String str = "hamster, diagram, private, dutch, cause, delay, private, meat, slide, toddler, razor, book, happy, fancy, gospel, tennis, maple, dilemma, loan, word, shrug, inflict, delay, opera";
			List<String> list = Arrays.stream(str.split(",")).map(String::trim).collect(Collectors.toList());
			String seed = Mnemonics.generateSeedFromWords(Language.ENGLISH, list);
			assertEquals("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c".toUpperCase(), seed.toUpperCase());
		}

		{
			String str = "all, hour, make, first, leader, extend, hole, alien, behind, guard, gospel, lava, path, output, census, museum, junior, mass, reopen, famous, sing, advance, salt, runway";
			List<String> list = Arrays.stream(str.split(",")).map(String::trim).collect(Collectors.toList());
			String seed = Mnemonics.generateSeedFromWords(Language.ENGLISH, list);
			assertEquals("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad".toUpperCase(), seed.toUpperCase());
		}

	}

}
