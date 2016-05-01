package org.pyjks;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.Test;

/**
 * Prepares JCEKS keystores that use features that are specific to JCE and are not supported by JKS keystores.
 */
public class JceKeystoreGeneratorTest extends PyJksTestCase
{
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
		PBEKeySpec keySpec = new PBEKeySpec("fibonacci".toCharArray(), new byte[]{1,1,2,3,5,8,13,21}, 999, 256);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		SecretKey key = factory.generateSecret(keySpec);

		generateSecretKeyStore("../keystores/jceks/PBKDF2WithHmacSHA1.jceks", key);
	}

	@Test
	public void jceks_AES() throws Exception
	{
		generateSecretKeyStore("../keystores/jceks/AES128.jceks", new SecretKeySpec(Hex.decodeHex("666e0221cc44c1fc4aabf458f9dfdd3c".toCharArray()), "AES"));
		generateSecretKeyStore("../keystores/jceks/AES256.jceks", new SecretKeySpec(Hex.decodeHex("e7d7c262668221787b6b5a0f687712fde4be52e9e7d7c262668221787b6b5a0f".toCharArray()), "AES"));
	}

	@Test
	public void jceks_unknown_type_of_sealed_object() throws Exception
	{
		// create a keystore with a SecretKeyEntry that has a serialized object inside of it that is *not* of type javax.crypto.SealedObject
		String filename = "../keystores/jceks/unknown_type_of_sealed_object.jceks";
		String alias = "mykey";
		String password = "12345678";

		generateManualSealedObjectStore(filename, password, alias, new DummyObject());
	}

	@Test
	public void jceks_unknown_type_inside_sealed_object() throws Exception
	{
		// create a keystore with a SecretKeyEntry with a proper SealedObject instance, but with an unexpected Java type encrypted inside the SealedObject
		String filename = "../keystores/jceks/unknown_type_inside_sealed_object.jceks";
		String alias = "mykey";
		String password = "12345678";

		// encrypt the enclosed serialized object with PBEWithMD5AndTripleDES, as the Sun JCE key store implementation does
		Cipher cipher = makePBECipher("PBEWithMD5AndTripleDES", Cipher.ENCRYPT_MODE, password, new byte[]{83, 79, 95, 83, 65, 76, 84, 89}, 42);

		SealedObject so = new SealedObject(new DummyObject(), cipher);
		generateManualSealedObjectStore(filename, password, alias, so);
	}


	@Test
	public void jceks_unknown_sealed_object_sealAlg() throws Exception
	{
		// create a keystore with a SecretKeyEntry with a proper SealedObject instance, but with an unexpected sealing algorithm
		String filename = "../keystores/jceks/unknown_sealed_object_sealAlg.jceks";
		String alias = "mykey";
		String password = "12345678";

		// encrypt the enclosed serialized object with PBEWithMD5AndTripleDES, as the Sun JCE key store implementation does
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(new byte[]{83, 79, 95, 83, 65, 76, 84, 89}, 42);
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKey pbeKey = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES").generateSecret(pbeKeySpec);

		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

		SealedObject so = new SealedObject(new DummyObject(), cipher);
		FieldUtils.writeField(so, "sealAlg", "nonsense", true);

		generateManualSealedObjectStore(filename, password, alias, so);
	}

}
