package org.pyjks;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Prepares a bunch of JCEKS key stores on disk for pyjks to parse and verify the contents of.
 */
public class JceKeystoreGeneratorTest
{
	@BeforeClass
	public static void setUpClass() throws Exception
	{
		File targetDirectory = new File("../keystores/jceks");
		FileUtils.forceMkdir(targetDirectory);
	}

	protected void generateSecretKeyStore(String filepath, SecretKey secretKey) throws Exception
	{
		generateSecretKeyStore(filepath, secretKey, "12345678", "12345678", "mykey");
	}

	protected void generateSecretKeyStore(String filepath, SecretKey secretKey, String keystorePassword, String keyPassword, String alias) throws Exception
	{
		KeyStore ks = KeyStore.getInstance("JCEKS");
		char[] ksPasswordChars = keystorePassword.toCharArray();
		ks.load(null, ksPasswordChars);

		if (secretKey != null)
			ks.setEntry(alias, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(keyPassword.toCharArray()));

		FileOutputStream fos = new FileOutputStream(filepath);
		ks.store(fos, ksPasswordChars);
		fos.close();
	}

	@Test
	public void jceks_empty() throws Exception
	{
		generateSecretKeyStore("../keystores/jceks/empty.jceks", null, "", "", "");
	}

	@Test
	public void jceks_DES() throws Exception
	{
		// Note: SunJCE's DESKeyFactory will construct a DESKey from the input bytes given by the DESKeySpec after correcting for parity bits,
		// so to ensure that the resulting key that gets stored is the exact same as our input bytes given here, we have to choose our
		// input key bytes in such a way that the parity bit corrections don't affect it.
		DESKeySpec keySpec = new DESKeySpec(Hex.decodeHex("4cf2fe915d082a43".toCharArray()));
		SecretKey key = SecretKeyFactory.getInstance("DES").generateSecret(keySpec);

		generateSecretKeyStore("../keystores/jceks/DES.jceks", key);
	}

	@Test
	public void jceks_DESede() throws Exception
	{
		// Same comments as for the DES case
		DESedeKeySpec keySpec = new DESedeKeySpec(Hex.decodeHex("675e5245e9673b4c8fc194ceec433b318c45c2e0675e5245".toCharArray()));
		SecretKey key = SecretKeyFactory.getInstance("DESede").generateSecret(keySpec);

		generateSecretKeyStore("../keystores/jceks/DESede.jceks", key);
	}

	@Test
	public void jceks_PBKDF2() throws Exception
	{
		PBEKeySpec keySpec = new PBEKeySpec("CCC".toCharArray(), new byte[]{1,2,3,4,5,6,7,8}, 999, 256);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		SecretKey key = factory.generateSecret(keySpec);

		generateSecretKeyStore("../keystores/jceks/PBKDF2.jceks", key);
	}

	@Test
	public void jceks_AES() throws Exception
	{
		generateSecretKeyStore("../keystores/jceks/AES128.jceks", new SecretKeySpec(Hex.decodeHex("666e0221cc44c1fc4aabf458f9dfdd3c".toCharArray()), "AES"));
		generateSecretKeyStore("../keystores/jceks/AES256.jceks", new SecretKeySpec(Hex.decodeHex("e7d7c262668221787b6b5a0f687712fde4be52e9e7d7c262668221787b6b5a0f".toCharArray()), "AES"));
	}

}
