package org.pyjks;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Test;

/**
 * Generates JKS/JCEKS keystores that use features available to either format.
 */
public class KeystoreGeneratorTest extends PyJksTestCase
{
	@Test
	public void generate_empty() throws Exception
	{
		generateKeyStore("JKS",   "../keystores/jks/empty.jks", null, null, "");
		generateKeyStore("JCEKS", "../keystores/jceks/empty.jceks", null, null, "");
	}

	@Test
	public void generate_RSA1024() throws Exception
	{
		KeyPair keyPair = generateKeyPair("RSA", 1024);
		Certificate cert = createSelfSignedCertificate(keyPair, "CN=RSA1024");
		Certificate[] certs = new Certificate[]{cert};

		generatePrivateKeyStore("JKS",   "../keystores/jks/RSA1024.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/RSA1024.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/RSA1024.py", keyPair, certs);
	}

	@Test
	public void generate_RSA2048_3certs() throws Exception
	{
		KeyPair keyPair = generateKeyPair("RSA", 2048);

		// these do not form a chain, but that doesn't really matter for our purposes
		Certificate cert1 = createSelfSignedCertificate(keyPair, "CN=RSA2048, O=1");
		Certificate cert2 = createSelfSignedCertificate(keyPair, "CN=RSA2048, O=2");
		Certificate cert3 = createSelfSignedCertificate(keyPair, "CN=RSA2048, O=3");
		Certificate[] certs = new Certificate[]{ cert1, cert2, cert3 };

		generatePrivateKeyStore("JKS",   "../keystores/jks/RSA2048_3certs.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/RSA2048_3certs.jceks", keyPair.getPrivate(), certs);

		// and while we have some certificates here anyway, we might as well produce some stores with those in them too
		String[] certAliases = new String[]{"cert1", "cert2", "cert3"};
		generateCertsKeyStore("JKS",   "../keystores/jks/3certs.jks", certs, certAliases);
		generateCertsKeyStore("JCEKS",   "../keystores/jceks/3certs.jceks", certs, certAliases);

		writePythonDataFile("../expected/RSA2048_3certs.py", keyPair, certs);
	}

	@Test
	public void generate_DSA2048() throws Exception
	{
		KeyPair keyPair = generateKeyPair("DSA", 2048);
		Certificate cert = createSelfSignedCertificate(keyPair, "CN=DSA2048");
		Certificate[] certs = new Certificate[]{ cert };

		generatePrivateKeyStore("JKS",   "../keystores/jks/DSA2048.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/DSA2048.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/DSA2048.py", keyPair, certs);
	}

	@Test
	public void generate_custom_entry_passwords() throws Exception
	{
		// create JKS and JCEKS keystores containing entries of each type, each with a different entry password
		Map<String, KeyStore.Entry> entriesByAlias = new HashMap<String, KeyStore.Entry>();
		Map<String, String> passwordsByAlias = new HashMap<String, String>();

		// produce some key material
		KeyPair keyPair = generateKeyPair("RSA", 2048);
		Certificate cert = createSelfSignedCertificate(keyPair, "CN=custom_entry_passwords");
		Certificate[] certs = new Certificate[]{ cert };

		SecretKey secretKey = new SecretKeySpec(Hex.decodeHex("3f680504c66cc25aae65d0fa49c526ec".toCharArray()), "AES");

		// write JKS keystore
		entriesByAlias.put("cert", new KeyStore.TrustedCertificateEntry(cert));
		entriesByAlias.put("private", new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), certs));
		passwordsByAlias.put("private", "private_password");

		generateKeyStore("JKS", "../keystores/jks/custom_entry_passwords.jks", entriesByAlias, passwordsByAlias, "store_password");

		// add secret key entries and write JCEKS keystore
		entriesByAlias.put("secret", new KeyStore.SecretKeyEntry(secretKey));
		passwordsByAlias.put("secret", "secret_password");

		generateKeyStore("JCEKS", "../keystores/jceks/custom_entry_passwords.jceks", entriesByAlias, passwordsByAlias, "store_password");

		writePythonDataFile("../expected/custom_entry_passwords.py", keyPair, certs);
	}

	@Test
	public void generate_duplicate_aliases() throws Exception
	{
		KeyPair keyPair = generateKeyPair("RSA", 1024);
		Certificate cert1 = createSelfSignedCertificate(keyPair, "CN=duplicate_aliases, O=1");
		Certificate cert2 = createSelfSignedCertificate(keyPair, "CN=duplicate_aliases, O=2");

		String[] aliases = new String[]{"my_alias", "my_alias"};
		int[] tags = new int[]{TAG_TRUSTED_CERT, TAG_TRUSTED_CERT};
		byte[][] entriesData = new byte[][]{
			encodeTrustedCert(cert1),
			encodeTrustedCert(cert2)
		};

		generateManualStore("JKS",   "../keystores/jks/duplicate_aliases.jks",     aliases, tags, entriesData, "12345678");
		generateManualStore("JCEKS", "../keystores/jceks/duplicate_aliases.jceks", aliases, tags, entriesData, "12345678");
	}

	@Test
	public void generate_non_ascii_jks_password() throws Exception
	{
		// The JKS keystore protector algorithm says that the password is expected to be ASCII but it doesn't enforce that,
		// so there's nothing stopping you from using non-ASCII passwords anyway. Let's generate one and see if we can parse it.
		KeyPair keyPair = generateKeyPair("RSA", 2048);

		Certificate cert = createSelfSignedCertificate(keyPair, "CN=non_ascii_password");
		Certificate[] certs = new Certificate[]{cert};

		// Note: prefer not to use the \\uXXXX syntax here because the Java compiler interprets them *prior* to lexing (!)
		// causing them to interfere with syntax ...
		String non_ascii_password = StringUtils.newStringUtf16Be(new byte[]{
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x28,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x76, (byte) 0xCA,
			(byte) 0x0C, (byte) 0xA0,
			(byte) 0x10, (byte) 0xDA,
			(byte) 0x00, (byte) 0x29,
		});

		generatePrivateKeyStore("JKS", "../keystores/jks/non_ascii_password.jks", keyPair.getPrivate(), certs, non_ascii_password, non_ascii_password, "mykey");

		writePythonDataFile("../expected/jks_non_ascii_password.py", keyPair, certs);
	}
}
