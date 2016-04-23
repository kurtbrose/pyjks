package org.pyjks;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.DigestOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.crypto.SecretKey;
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
	public String toPythonString(byte[] data, int bytesPerLine)
	{
		char[] hexChars = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e','f'};

		StringBuffer sb = new StringBuffer();
		sb.append('"');
		for (int i=0; i < data.length; i++) {
			sb.append("\\x");
			// Note: Java promotes bytes to ints when doing any arithmetic on them (including bitwise operators),
			// so it doesn't matter whether we use >> or >>> as long as we null out extended sign bits with the bitwise AND first.
			sb.append(hexChars[(data[i] & 0xF0) >> 4]);
			sb.append(hexChars[(data[i] & 0x0F)]);
			if ((i+1) % bytesPerLine == 0) {
				sb.append("\" +\\\r\n\"");
			}
		}
		sb.append('"');
		return sb.toString();
	}

	public String toPythonString(byte[] data)
	{
		return toPythonString(data, 32);
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
		dos.writeInt(3); // secret key tag
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

	protected void generatePrivateKeyStore(String filepath, PrivateKey privateKey, Certificate[] chain) throws Exception
	{
		generatePrivateKeyStore(filepath, privateKey, chain, "12345678", "12345678", "mykey");
	}

	protected void generatePrivateKeyStore(String filepath, PrivateKey privateKey, Certificate[] chain, String keystorePassword, String keyPassword, String alias) throws Exception
	{
		KeyStore ks = KeyStore.getInstance("JCEKS");
		char[] ksPasswordChars = keystorePassword.toCharArray();
		ks.load(null, ksPasswordChars);

		if (privateKey != null)
			ks.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, chain), new KeyStore.PasswordProtection(keyPassword.toCharArray()));

		FileOutputStream fos = new FileOutputStream(filepath);
		ks.store(fos, ksPasswordChars);
		fos.close();
	}

	protected Certificate createSelfSignedCertificate(KeyPair keyPair, String dn) throws Exception
	{
		// Note: producing a self-signed certificate can be done through the JRE implementation as well,
		// but not in any portable or documented way (see sun.security.tools.keytool.CertAndKeyGen)
		Security.addProvider(new BouncyCastleProvider());
		try
		{
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();

			X500Name subject = new X500Name(dn);
			X500Name issuer = subject;
			BigInteger serial = BigInteger.valueOf(0);
			Date notBefore = new Date(System.currentTimeMillis());
			Date notAfter = new Date(System.currentTimeMillis() + 2*365*86400000L);

			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);
			ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
			X509CertificateHolder holder = certBuilder.build(signer);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);

			return cert;
		}
		finally
		{
			Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
		}
	}
}
