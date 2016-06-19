package org.pyjks;

import java.io.File;
import java.lang.reflect.Constructor;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Hashtable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.keystore.bc.BcKeyStoreSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), MAC, "", new byte[]{1,2,3,4,5,6,7,8}, 1000, 16)));
		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), MAC, "", new byte[]{1,2,3,4,5,6,7,8}, 1000, 17)));
		System.out.println(toPythonString(generatePkcs12DerivedKey(new SHA1Digest(), KEY, "", new byte[]{-65,10,-86,79,-124,-76,78,65,22,10,17,-73,-19,-104,88,-96,-107,59,75,-8}, 2010, 2)));

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

	protected byte[] encryptPBEWithSHAAndTwofishCBC(byte[] input, String password, byte[] salt, int iterationCount) throws Exception
	{
		Provider bcProv = Security.getProvider("BC");
		if (bcProv == null)
			Security.addProvider(new BouncyCastleProvider());

		try
		{
			Cipher c = makePBECipher("PBEWithSHAAndTwofish-CBC", Cipher.ENCRYPT_MODE, password, salt, iterationCount);
			return c.doFinal(input);
		}
		finally
		{
			if (bcProv == null)
				Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

	protected byte[] encryptPBEWithSHAAnd3KeyTripleDESCBC(byte[] input, String password, byte[] salt, int iterationCount) throws Exception
	{
		Provider bcProv = Security.getProvider("BC");
		if (bcProv == null)
			Security.addProvider(new BouncyCastleProvider());

		try
		{
			Cipher c = makePBECipher("PBEWithSHAAnd3-KeyTripleDES-CBC", Cipher.ENCRYPT_MODE, password, salt, iterationCount);
			return c.doFinal(input);
		}
		finally
		{
			if (bcProv == null)
				Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

	@Test
	public void generatePBEWithSHAAndTwofishCBCTestVectors() throws Exception
	{
		String fancyPassword = StringUtils.newStringUtf16Be(new byte[]{
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x28,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x76, (byte) 0xCA,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x29,
		});
		System.out.println(toPythonString(encryptPBEWithSHAAndTwofishCBC("sample".getBytes("UTF-8"), "mypassword", new byte[]{1,2,3,4,5,6,7,8}, 1000)));
		System.out.println(toPythonString(encryptPBEWithSHAAndTwofishCBC("sample".getBytes("UTF-8"), fancyPassword, new byte[]{1,2,3,4,5,6,7,8}, 1000)));

		System.out.println(toPythonString(encryptPBEWithSHAAndTwofishCBC("-------16-------".getBytes("UTF-8"), "mypassword", new byte[]{1,2,3,4,5,6,7,8}, 1000)));
		System.out.println(toPythonString(encryptPBEWithSHAAndTwofishCBC("-------16-------".getBytes("UTF-8"), fancyPassword, new byte[]{1,2,3,4,5,6,7,8}, 1000)));
	}

	@Test
	public void generatePBEWithSHAAnd3KeyTripleDESCBCTestVectors() throws Exception
	{
		String fancyPassword = StringUtils.newStringUtf16Be(new byte[]{
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x28,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x76, (byte) 0xCA,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x29,
		});
		System.out.println(toPythonString(encryptPBEWithSHAAnd3KeyTripleDESCBC("sample".getBytes("UTF-8"), "mypassword", new byte[]{1,2,3,4,5,6,7,8}, 1000)));
		System.out.println(toPythonString(encryptPBEWithSHAAnd3KeyTripleDESCBC("sample".getBytes("UTF-8"), fancyPassword, new byte[]{1,2,3,4,5,6,7,8}, 1000)));

		System.out.println(toPythonString(encryptPBEWithSHAAnd3KeyTripleDESCBC("-------16-------".getBytes("UTF-8"), "mypassword", new byte[]{1,2,3,4,5,6,7,8}, 1000)));
		System.out.println(toPythonString(encryptPBEWithSHAAnd3KeyTripleDESCBC("-------16-------".getBytes("UTF-8"), fancyPassword, new byte[]{1,2,3,4,5,6,7,8}, 1000)));
	}

	protected void populateChristmasStore(KeyStore ks, char[] passwordChars, KeyPair keyPair, SecretKey secretKey, SecretKey plainKey, Certificate cert, byte[] storedValue) throws Exception
	{
		Certificate[] certs = new Certificate[]{cert};

		ks.setCertificateEntry("cert", cert);
		ks.setKeyEntry("sealed_private_key", keyPair.getPrivate(), passwordChars, certs);
		ks.setKeyEntry("sealed_public_key", keyPair.getPublic(), passwordChars, null);
		ks.setKeyEntry("sealed_secret_key", secretKey, passwordChars, null);
		ks.setKeyEntry("stored_value", storedValue, null);
		addPlainKeyEntry(ks, "plain_key", plainKey, new Certificate[]{});
	}

	protected void populateCustomEntryPasswordsStore(KeyStore ks, KeyPair keyPair, SecretKey secretKey, Certificate[] certs) throws Exception
	{
		ks.setKeyEntry("sealed_private_key", keyPair.getPrivate(), "private_password".toCharArray(), certs);
		ks.setKeyEntry("sealed_public_key", keyPair.getPublic(), "public_password".toCharArray(), certs);
		ks.setKeyEntry("sealed_secret_key", secretKey, "secret_password".toCharArray(), certs);
	}

	/**
	 * Adds an entry of type KEY to the given (BKS) keystore.
	 */
	@SuppressWarnings({"unchecked", "rawtypes"})
	protected void addPlainKeyEntry(KeyStore store, String alias, Key key, Certificate[] chain) throws Exception
	{
		// it's no longer possible to create BKS entries of type 'KEY', but we still want to able to handle them on the python side,
		// so we'll have to dig into the internals of BKS keystores a bit to get such an entry created
		KeyStoreSpi spi = (KeyStoreSpi) FieldUtils.readField(store, "keyStoreSpi", true);
		if (!(spi instanceof BcKeyStoreSpi))
			throw new RuntimeException("Wrong keystore supplied, must be a BC keystore");

		BcKeyStoreSpi bcSpi = (BcKeyStoreSpi) spi;
		Class<?> storeEntryClazz = Class.forName(BcKeyStoreSpi.class.getName() + "$StoreEntry");
		Constructor<?> constr = storeEntryClazz.getDeclaredConstructor(BcKeyStoreSpi.class, String.class, Date.class, int.class, Object.class, Certificate[].class);
		constr.setAccessible(true);
		Object storeEntry = constr.newInstance(bcSpi, alias, new Date(), 2 /*BcKeyStoreSpi.KEY*/, key, chain);

		Hashtable entryTable = (Hashtable) FieldUtils.readField(bcSpi, "table", true);
		entryTable.put(alias, storeEntry);
	}

	@Test
	public void bks_empty() throws Exception
	{
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		try
		{
			generateKeyStore("BKS-V1", "../keystores/bks/empty.bksv1", null, null, "");
			generateKeyStore("BKS",    "../keystores/bks/empty.bksv2", null, null, "");
			generateKeyStore("UBER",   "../keystores/uber/empty.uber", null, null, "");
		}
		catch (Exception e)
		{
			System.err.println(e.getMessage());
			throw e;
		}
		finally
		{
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

	/**
	 * Generates BKS and UBER keystores containing all possible entry types (past and present).
	 */
	@Test
	public void bks_christmas_store() throws Exception
	{
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		try
		{
			// generate a bunch of key material of all different supported types
			SecretKey aesKey = new SecretKeySpec(Hex.decodeHex("3f680504c66cc25aae65d0fa49c526ec".toCharArray()), "AES");
			SecretKey desKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESKeySpec(Hex.decodeHex("4cf2fe915d082a43".toCharArray())));

			KeyPair keyPair = generateKeyPair("RSA", 1024);
			Certificate cert = createSelfSignedCertificate(keyPair, "CN=RSA1024");
			char[] passwordChars = "12345678".toCharArray();

			// generate one of each store type
			KeyStore ks = KeyStore.getInstance("BKS-V1");
			ks.load(null, null);
			populateChristmasStore(ks, passwordChars, keyPair, aesKey, desKey, cert, new byte[]{2,3,5,7,11,13,17,19,23});
			ks.store(FileUtils.openOutputStream(new File("../keystores/bks/christmas.bksv1")), passwordChars);

			ks = KeyStore.getInstance("BKS");
			ks.load(null, null);
			populateChristmasStore(ks, passwordChars, keyPair, aesKey, desKey, cert, new byte[]{2,3,5,7,11,13,17,19,23});
			ks.store(FileUtils.openOutputStream(new File("../keystores/bks/christmas.bksv2")), passwordChars);

			ks = KeyStore.getInstance("UBER");
			ks.load(null, null);
			populateChristmasStore(ks, passwordChars, keyPair, aesKey, desKey, cert, new byte[]{2,3,5,7,11,13,17,19,23});
			ks.store(FileUtils.openOutputStream(new File("../keystores/uber/christmas.uber")), passwordChars);

			writePythonDataFile("../expected/bks_christmas.py", keyPair, new Certificate[]{cert});
		}
		catch (Exception e)
		{
			System.err.println(e.getMessage());
			throw e;
		}
		finally
		{
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

	/**
	 * Generates BKS and UBER keystores containing keys encrypted with passwords that are different from
	 * the store password.
	 */
	@Test
	public void bks_custom_entry_passwords() throws Exception
	{
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		try
		{
			KeyPair keyPair = generateKeyPair("RSA", 1024);
			Certificate cert = createSelfSignedCertificate(keyPair, "CN=custom_entry_passwords1");
			Certificate[] certs = new Certificate[]{cert};

			SecretKey aesKey = new SecretKeySpec(Hex.decodeHex("05e2aaa5e7cdf50be459ea6c64f01b21".toCharArray()), "AES");

			char[] store_password = "store_password".toCharArray();

			// generate one of each store type
			KeyStore ks = KeyStore.getInstance("BKS-V1");
			ks.load(null, null);
			populateCustomEntryPasswordsStore(ks, keyPair, aesKey, certs);
			ks.store(FileUtils.openOutputStream(new File("../keystores/bks/custom_entry_passwords.bksv1")), store_password);

			ks = KeyStore.getInstance("BKS");
			ks.load(null, null);
			populateCustomEntryPasswordsStore(ks, keyPair, aesKey, certs);
			ks.store(FileUtils.openOutputStream(new File("../keystores/bks/custom_entry_passwords.bksv2")), store_password);

			ks = KeyStore.getInstance("UBER");
			ks.load(null, null);
			populateCustomEntryPasswordsStore(ks, keyPair, aesKey, certs);
			ks.store(FileUtils.openOutputStream(new File("../keystores/uber/custom_entry_passwords.uber")), store_password);

			writePythonDataFile("../expected/bks_custom_entry_passwords.py", keyPair, new Certificate[]{cert});
		}
		catch (Exception e)
		{
			System.err.println(e.getMessage());
			throw e;
		}
		finally
		{
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

}
