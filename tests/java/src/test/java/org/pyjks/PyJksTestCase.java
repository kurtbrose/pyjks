package org.pyjks;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.DigestOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Superclass for pyjks test case generators; mostly here to provide utility functions.
 */
public class PyJksTestCase
{
	public static int TAG_PRIVATE_KEY = 1;
	public static int TAG_TRUSTED_CERT = 2;
	public static int TAG_SECRET_KEY = 3;

	public static String toPythonString(byte[] data, int bytesPerLine, String leftPadding)
	{
		char[] hexChars = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e','f'};
		leftPadding = (leftPadding == null ? "" : leftPadding);

		StringBuffer sb = new StringBuffer();
		sb.append(leftPadding);
		sb.append("b\"");
		for (int i=0; i < data.length; i++)
		{
			sb.append("\\x");
			// Note: Java promotes bytes to ints when doing any arithmetic on them (including bitwise operators),
			// so it doesn't matter whether we use >> or >>> as long as we null out extended sign bits with the bitwise AND first.
			sb.append(hexChars[(data[i] & 0xF0) >> 4]);
			sb.append(hexChars[(data[i] & 0x0F)]);
			if ((i+1) % bytesPerLine == 0 && i < data.length - 1) { // reached max. bytes for this line and there are remaining bytes left
				sb.append("\" + \\\n"+leftPadding+"b\"");
			}
		}
		sb.append('"');
		return sb.toString();
	}

	public static String toPythonString(byte[] data)
	{
		return toPythonString(data, 32, "");
	}

	/**
	 * Creates a Python source file at the given location which defines three variables 'public_key', 'private_key'
	 * and 'certs', containing byte strings with the encoded form of the given keypair and certificates.
	 *
	 * The 'public_key' variable contains a byte string with the X.509 SubjectPublicKeyInfo representation of the public key.
	 * The 'private_key' variable contains a byte string with the PKCS#8 representation of the private key.
	 * The 'certs' variable contains a list with the X.509 DER representation of each given certificate in order.
	 *
	 * The main purpose of this method is to be able to avoid having to include these large byte strings into the test
	 * case files, and instead be able to reference them through Python's module system.
	 *
	 * E.g. outputting expected/mytestcase.py using this method allows the Python test cases to reference
	 * expected.mytestcase.private_key and expected.mytestcase.certs to access the expected values that should be found
	 * after decoding that test's keystore.
	 */
	protected void writePythonDataFile(String filename, KeyPair keyPair, Certificate[] certs) throws Exception
	{
		String privateKeyPadding = StringUtils.repeat(" ", "private_key = ".length());
		String publicKeyPadding  = StringUtils.repeat(" ", "public_key = ".length());
		String certsPadding      = StringUtils.repeat(" ", "certs = [".length());

		StringBuffer sb = new StringBuffer();
		sb.append("public_key = ");
		sb.append(StringUtils.stripStart(toPythonString(keyPair.getPublic().getEncoded(), 32, publicKeyPadding), null));
		sb.append("\n");
		sb.append("private_key = ");
		sb.append(StringUtils.stripStart(toPythonString(keyPair.getPrivate().getEncoded(), 32, privateKeyPadding), null));
		sb.append("\n");
		sb.append("certs = [");
		for (int i = 0; i < certs.length; i++)
		{
			String toAppend = toPythonString(certs[i].getEncoded(), 32, certsPadding);
			toAppend = (i == 0 ? StringUtils.stripStart(toAppend, null) : toAppend);
			sb.append(toAppend);
			sb.append(i < certs.length - 1 ? ",\n" : "");
		}
		sb.append("]\n");

		FileUtils.writeStringToFile(new File(filename), sb.toString());
	}

	protected KeyPair generateKeyPair(String algorithm, int size) throws Exception
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(size);
		return keyPairGenerator.generateKeyPair();
	}

	protected void generateKeyStore(String storeType, String filepath, Map<String, KeyStore.Entry> entriesByAlias, Map<String, String> entryPasswordsByAlias, String storePassword) throws Exception
	{
		// avoid the need for some null checks in the remainder of the code below
		if (entriesByAlias == null)
			entriesByAlias = new HashMap<String, KeyStore.Entry>();
		if (entryPasswordsByAlias == null)
			entryPasswordsByAlias = new HashMap<String, String>();

		KeyStore ks = KeyStore.getInstance(storeType);
		char[] storePasswordChars = storePassword.toCharArray();
		ks.load(null, storePasswordChars);

		for (String alias : entriesByAlias.keySet())
		{
			KeyStore.Entry entry = entriesByAlias.get(alias);
			if (entry == null)
				continue;

			// trusted certificates don't need password protection (and will complain if you provide it)
			KeyStore.PasswordProtection passwordProtection = null;
			if (!(entry instanceof KeyStore.TrustedCertificateEntry))
			{
				String entryPassword = entryPasswordsByAlias.get(alias);
				if (entryPassword == null)
					entryPassword = storePassword;

				// Note: there's no point specifying a protection algorithm/parameters to the KeyStore.PasswordProtection instance,
				// the default KeyStoreSpi.setEntry implementation uses it only to grab the password and nothing else.
				// Only the PKCS12 keystore SPI appears to honor custom protection algorithm/parameters.
				passwordProtection = new KeyStore.PasswordProtection(entryPassword.toCharArray());
			}

			ks.setEntry(alias, entry, passwordProtection);
		}

		// use FileUtils.openOutputStream so we don't have to manually create any intermediate directories in filepath
		FileOutputStream fos = FileUtils.openOutputStream(new File(filepath));
		ks.store(fos, storePasswordChars);
		fos.close();
	}

	protected void generatePrivateKeyStore(String storeType, String filepath, PrivateKey privateKey, Certificate[] chain) throws Exception
	{
		generatePrivateKeyStore(storeType, filepath, privateKey, chain, "12345678", "12345678", "mykey");
	}

	protected void generatePrivateKeyStore(String storeType, String filepath, PrivateKey privateKey, Certificate[] chain, String storePassword, String keyPassword, String alias) throws Exception
	{
		Map<String, KeyStore.Entry> entriesByAlias = new HashMap<String, KeyStore.Entry>();
		Map<String, String> passwordsByAlias = new HashMap<String, String>();

		if (privateKey != null)
		{
			entriesByAlias.put(alias, new KeyStore.PrivateKeyEntry(privateKey, chain));
			passwordsByAlias.put(alias, keyPassword);
		}

		generateKeyStore(storeType, filepath, entriesByAlias, passwordsByAlias, storePassword);
	}

	protected void generateCertKeyStore(String storeType, String filepath, Certificate cert) throws Exception
	{
		generateCertsKeyStore(storeType, filepath, new Certificate[]{cert}, new String[]{"mycert"}, "12345678");
	}

	protected void generateCertsKeyStore(String storeType, String filepath, Certificate[] certs, String[] aliases) throws Exception
	{
		generateCertsKeyStore(storeType, filepath, certs, aliases, "12345678");
	}

	protected void generateCertsKeyStore(String storeType, String filepath, Certificate[] certs, String[] aliases, String storePassword) throws Exception
	{
		Map<String, KeyStore.Entry> entriesByAlias = new HashMap<String, KeyStore.Entry>();

		if (certs != null && aliases != null)
		{
			for (int i=0; i < certs.length; i++)
				entriesByAlias.put(aliases[i], new KeyStore.TrustedCertificateEntry(certs[i]));
		}

		generateKeyStore(storeType, filepath, entriesByAlias, null, storePassword);
	}

	protected void generateSecretKeyStore(String filepath, SecretKey secretKey) throws Exception
	{
		generateSecretKeyStore(filepath, secretKey, "12345678", "12345678", "mykey");
	}

	protected void generateSecretKeyStore(String filepath, SecretKey secretKey, String storePassword, String keyPassword, String alias) throws Exception
	{
		Map<String, KeyStore.Entry> entriesByAlias = new HashMap<String, KeyStore.Entry>();
		Map<String, String> passwordsByAlias = new HashMap<String, String>();

		if (secretKey != null)
		{
			entriesByAlias.put(alias, new KeyStore.SecretKeyEntry(secretKey));
			passwordsByAlias.put(alias, keyPassword);
		}

		generateKeyStore("JCEKS", filepath, entriesByAlias, passwordsByAlias, storePassword);
	}

	protected MessageDigest getJceStoreDigest(String keystorePassword)
	{
		char[] password = keystorePassword.toCharArray();
		MessageDigest md = null;
		try
		{
			md = MessageDigest.getInstance("SHA-1");
			byte[] passwdBytes = new byte[password.length * 2];

			for (int i = 0, j = 0; i < password.length; i++)
			{
				passwdBytes[j++] = (byte) (password[i] >> 8);
				passwdBytes[j++] = (byte) password[i];
			}
			md.update(passwdBytes);
			for (int i = 0; i < passwdBytes.length; i++)
				passwdBytes[i] = 0;

			md.update("Mighty Aphrodite".getBytes("UTF8"));
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new RuntimeException(e);
		}
		catch (UnsupportedEncodingException e)
		{
			throw new RuntimeException(e);
		}
		return md;
	}

	/**
	 * Generates a JCEKS keystore with a single SecretKey entry whose serialized Java object is provided manually
	 * (i.e. replacing the SealedObject that the JCE key store implementation would otherwise automatically generate).
	 *
	 * Main purpose is to test the behaviour of pyjks when given unepxected serialized java objects either at or inside the SealedObject level.
	 */
	protected void generateManualSealedObjectStore(String filename, String storePassword, String alias, Object sealedObject) throws Exception
	{
		MessageDigest md = getJceStoreDigest(storePassword);

		DataOutputStream dos = new DataOutputStream(new DigestOutputStream(new BufferedOutputStream(new FileOutputStream(filename)), md));
		dos.writeInt(0xCECECECE); // JCE magic bytes
		dos.writeInt(2); // keystore version
		dos.writeInt(1); // number of entries
		dos.writeInt(TAG_SECRET_KEY);
		dos.writeShort(alias.length());
		dos.write(alias.getBytes("UTF-8"));
		dos.writeLong(System.currentTimeMillis());

		ObjectOutputStream oos = new ObjectOutputStream(dos);
		oos.writeObject(sealedObject);
		oos.flush();

		dos.write(md.digest());
		dos.flush();
		oos.close();
	}

	protected void generateManualStore(String storeType, String filename, String[] aliases, int[] tags, byte[][] entriesData, String storePassword) throws Exception
	{
		MessageDigest md = getJceStoreDigest(storePassword);

		DataOutputStream dos = new DataOutputStream(new DigestOutputStream(new BufferedOutputStream(new FileOutputStream(filename)), md));
		dos.writeInt("JCEKS".equals(storeType) ? 0xCECECECE : 0xFEEDFEED);
		dos.writeInt(2); // keystore version
		dos.writeInt(aliases.length); // number of entries

		for (int i=0; i < aliases.length; i++)
		{
			String alias = aliases[i];
			int tag = tags[i];
			byte[] data = entriesData[i];

			dos.writeInt(tag);
			dos.writeShort(alias.length());
			dos.write(alias.getBytes("UTF-8"));
			dos.writeLong(System.currentTimeMillis());
			dos.write(data);
		}

		dos.write(md.digest());
		dos.flush();
		dos.close();
	}

	protected Certificate createSelfSignedCertificate(KeyPair keyPair, String dn) throws Exception
	{
		// Note: producing a self-signed certificate can be done through the JRE implementation as well,
		// but not in any portable or documented way (see sun.security.tools.keytool.CertAndKeyGen)
		Provider bcProv = Security.getProvider("BC");
		if (bcProv == null)
			Security.addProvider(new BouncyCastleProvider());

		try
		{
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			String sigAlgorithmName = "";
			if (keyPair.getPrivate() instanceof RSAPrivateKey) {
				sigAlgorithmName = "SHA256WithRSAEncryption";
			} else if (keyPair.getPrivate() instanceof DSAPrivateKey) {
				sigAlgorithmName = "SHA1withDSA";
			} else {
				throw new RuntimeException("Don't know which signing algorithm to use for private keys of type " + keyPair.getPrivate().getAlgorithm());
			}

			X500Name subject = new X500Name(dn);
			X500Name issuer = subject;
			BigInteger serial = BigInteger.valueOf(0);
			Date notBefore = new Date(System.currentTimeMillis());
			Date notAfter = new Date(System.currentTimeMillis() + 2*365*86400000L);

			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);
			ContentSigner signer = new JcaContentSignerBuilder(sigAlgorithmName).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
			X509CertificateHolder holder = certBuilder.build(signer);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);

			return cert;
		}
		finally
		{
			if (bcProv == null)
				Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}

	protected byte[] encodeTrustedCert(Certificate cert) throws Exception
	{
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(bos);

		byte[] encoded = cert.getEncoded();
		String type = cert.getType();
		dos.writeShort(type.length());
		dos.write(type.getBytes("UTF-8"));
		dos.writeInt(encoded.length);
		dos.write(encoded);
		dos.flush();
		dos.close();

		return bos.toByteArray();
	}

	protected Cipher makePBECipher(String algorithm, int mode, String password, byte[] salt, int iterationCount) throws Exception
	{
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
		SecretKey pbeKey = SecretKeyFactory.getInstance(algorithm).generateSecret(pbeKeySpec);

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(mode, pbeKey, pbeParamSpec);
		return cipher;

	}

	protected byte[] encryptPBEWithMD5AndTripleDES(byte[] input, String password, byte[] salt, int iterationCount) throws Exception
	{
		Cipher c = makePBECipher("PBEWithMD5AndTripleDES", Cipher.ENCRYPT_MODE, password, salt, iterationCount);
		return c.doFinal(input);
	}

}
