package io.zdp.common.utils;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang3.StringUtils;

/**
 * Utilities for converting data from/to strings.
 */
public class StringHelper {

	static byte[] p_util_hexdigit = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, };

	private static byte HexDigit(int c) {
		return p_util_hexdigit[c];
	}

	public static List<Integer> ParseHex(String str) {

		// convert hex dump to vector
		List<Integer> vch = new ArrayList<>();
		int p = 0;
		char[] arr = str.toCharArray();

		while (true) {

			while (Character.isSpace(arr[p]))
				p++;

			byte c = HexDigit(arr[p++]);

			if (c == -1)
				break;

			int n = (c << 4);

			c = HexDigit(p++);

			if (c == -1)
				break;

			n |= c;

			vch.add(n);
		}

		return vch;
	}

	public static String format(double val) {
		DecimalFormat myFormatter = new DecimalFormat("###,###.###");
		String output = myFormatter.format(val);
		return output;
	}

	public static String formatFraction(double val) {
		DecimalFormat myFormatter = new DecimalFormat("###,###.########");
		String output = myFormatter.format(val);
		return output;
	}

	public static String toHexString(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
		return DatatypeConverter.parseHexBinary(s);
	}

	public static String cleanUpMemo(final String memo) {
		final StringBuilder sb = new StringBuilder();
		if (StringUtils.isNotBlank(memo)) {
			for (Character c : memo.toCharArray()) {
				if (Character.isLetterOrDigit(c)) {
					sb.append(c);
				} else if (c == ' ') {
					sb.append(c);
				} else if (c == '-') {
					sb.append(c);
				} else if (c == '_') {
					sb.append(c);
				}
			}
		}

		String result = sb.toString().trim();

		if (result.length() > 64) {
			result = result.substring(0, 63);
		}

		return result;
	}

}
