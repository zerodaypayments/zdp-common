package io.zdp.common.crypto;

import org.junit.Test;

import io.zdp.common.utils.StringHelper;
import junit.framework.TestCase;

public class TestStringHelper extends TestCase {

	@Test
	public void test() {

		String str = "REF2342343";
		assertEquals(str, StringHelper.cleanUpMemo(str));
		assertEquals(str, StringHelper.cleanUpMemo("REF2342343    "));
		assertEquals(str, StringHelper.cleanUpMemo("    REF2342343    "));
		assertEquals("REF2342343  2", StringHelper.cleanUpMemo("REF2342343  @#$2  "));
		assertEquals("REF2342343  2_", StringHelper.cleanUpMemo("REF2342343  @#$2_"));
	}
}
