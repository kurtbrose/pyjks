package org.pyjks;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
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
