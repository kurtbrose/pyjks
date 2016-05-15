package org.pyjks;

import org.apache.commons.codec.binary.StringUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Test;

public class BksKeystoreGeneratorTest extends PyJksTestCase
{
	protected byte[] generatePkcs12DerivedKey(Digest digest, int purpose, String password, byte[] salt, int iterationCount, int numDesiredBytes) throws Exception
	{
		PKCS12ParametersGenerator gen = new PKCS12ParametersGenerator(digest);
		byte[] password_bytes = PBEParametersGenerator.PKCS12PasswordToBytes(password.toCharArray());
		gen.init(password_bytes, salt, iterationCount);

		if (purpose == PKCS12ParametersGenerator.MAC_MATERIAL)
		{
			KeyParameter params = (KeyParameter) gen.generateDerivedMacParameters(numDesiredBytes*8);
			return params.getKey();
		}
		else
		{
			ParametersWithIV params = (ParametersWithIV) gen.generateDerivedParameters(numDesiredBytes*8, numDesiredBytes*8);
			if (purpose == PKCS12ParametersGenerator.KEY_MATERIAL)
			{
				return ((KeyParameter) params.getParameters()).getKey();
			}
			else if (purpose == PKCS12ParametersGenerator.IV_MATERIAL)
			{
				return params.getIV();
			}
		}
		throw new RuntimeException("No such purpose byte");
	}

	@Test
	public void generatePkcs12KDFTestVectors() throws Exception
	{
		int MAC = PKCS12ParametersGenerator.MAC_MATERIAL;
		int KEY = PKCS12ParametersGenerator.KEY_MATERIAL;
		int IV = PKCS12ParametersGenerator.IV_MATERIAL;

		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), MAC, "password", new byte[]{1,2,3,4,5,6,7,8}, 1000, 16)));

		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), MAC, "password", new byte[]{1,2,3,4,5,6,7,8}, 1000, 17)));
		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), KEY, "password", new byte[]{1,2,3,4,5,6,7,8}, 1000, 17)));
		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), IV,  "password", new byte[]{1,2,3,4,5,6,7,8}, 1000, 17)));

		String fancyPassword = StringUtils.newStringUtf16Be(new byte[]{
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x28,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x76, (byte) 0xCA,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x29,
		});
		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), KEY, fancyPassword, new byte[]{1,2,3,4,5,6,7,8}, 1000, 129)));
	}
}
