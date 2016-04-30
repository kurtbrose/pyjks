package org.pyjks;

import org.junit.Test;

public class MiscTest extends PyJksTestCase
{
	/**
	 * Encrypt some known data with PBEWithMD5AndTripleDES to verify correct decryption in python.
	 * In particular, exercise the edge case where the two salt halves are equal, because there's a bug in the JCE lurking there
	 * (see the python side for details)
	 */
	@Test
	public void generate_PBEWithMD5AndTripleDES_samples() throws Exception
	{
		byte[] output1 = encryptPBEWithMD5AndTripleDES("sample".getBytes(), "my_password", new byte[]{1,2,3,4,5,6,7,8}, 42);
		byte[] output2 = encryptPBEWithMD5AndTripleDES("sample".getBytes(), "my_password", new byte[]{1,2,3,4,1,2,3,4}, 42); // special case for SunJCE's PBEWithMD5AndTripleDES: identical salt halves
		byte[] output3 = encryptPBEWithMD5AndTripleDES("sample".getBytes(), "my_password", new byte[]{1,2,3,4,1,2,3,5}, 42); // control case for the previous one

		System.out.println(toPythonString(output1));
		System.out.println(toPythonString(output2));
		System.out.println(toPythonString(output3));
	}
}
