package org.pyjks;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.io.FileUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Generates JKS/JCEKS keystores that use features available to either format.
 */
public class KeystoreGeneratorTest extends PyJksTestCase
{
	@BeforeClass
	public static void setUpClass() throws Exception
	{
		FileUtils.forceMkdir(new File("../keystores/jks"));
		FileUtils.forceMkdir(new File("../keystores/jceks"));
		FileUtils.forceMkdir(new File("../expected"));
	}

	@Test
	public void generate_empty() throws Exception
	{
		generatePrivateKeyStore("JKS",   "../keystores/jks/empty.jks",     null, null, "", "", "");
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/empty.jceks", null, null, "", "", "");
	}

	@Test
	public void generate_RSA1024() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Certificate cert = createSelfSignedCertificate(keyPair, "CN=RSA1024");
		Certificate[] certs = new Certificate[]{cert};

		generatePrivateKeyStore("JKS",   "../keystores/jks/RSA1024.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/RSA1024.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/RSA1024.py", keyPair.getPrivate(), certs);
	}

	@Test
	public void generate_RSA2048_3certs() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

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

		writePythonDataFile("../expected/RSA2048_3certs.py", keyPair.getPrivate(), certs);
	}

	@Test
	public void generate_DSA2048() throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// these do not form a chain, but that doesn't really matter for our purposes
		Certificate cert = createSelfSignedCertificate(keyPair, "CN=DSA2048");
		Certificate[] certs = new Certificate[]{ cert };

		generatePrivateKeyStore("JKS",   "../keystores/jks/DSA2048.jks",     keyPair.getPrivate(), certs);
		generatePrivateKeyStore("JCEKS", "../keystores/jceks/DSA2048.jceks", keyPair.getPrivate(), certs);

		writePythonDataFile("../expected/DSA2048.py", keyPair.getPrivate(), certs);
	}

	@Test
	public void generate_non_ascii_jks_password() throws Exception
	{
		// The JKS keystore protector algorithm says that the password is expected to be ASCII but it doesn't enforce that,
		// so there's nothing stopping you from using non-ASCII passwords anyway. Let's generate one and see if we can parse it.
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

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

		writePythonDataFile("../expected/jks_non_ascii_password.py", keyPair.getPrivate(), certs);
	}
}
