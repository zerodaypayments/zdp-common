package io.zdp.common.utils;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

/**
 * Utilities for converting data from/to strings.
 */
public class StringHelper {

	static byte[] p_util_hexdigit =
		{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
		  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

	private static byte HexDigit(int c)
	{
	    return p_util_hexdigit[c];
	}

	
	public static List<Integer> ParseHex(String str)
	{
		
	    // convert hex dump to vector
	    List<Integer> vch = new ArrayList<>();
	    int p = 0;
	    char[] arr = str.toCharArray();
	    
	    while (true)
	    {
	    	
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

}
