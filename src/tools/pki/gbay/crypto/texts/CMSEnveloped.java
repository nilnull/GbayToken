/*    */package tools.pki.gbay.crypto.texts;

import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CMSEnveloped {
	public static byte[] encrypt(X509Certificate certificate, String data)
			throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		//String algo = CMSEnvelopedDataGenerator.AES128_CBC;
		CMSEnvelopedDataGenerator fact = new CMSEnvelopedDataGenerator();

		fact.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(
				certificate).setProvider("BC"));
		CMSTypedData msg = new CMSProcessableByteArray(data.getBytes());

		CMSEnvelopedData ed = fact.generate(msg,
				new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
						.setProvider("BC").build());
		return ed.getEncoded();
	}

	@SuppressWarnings("rawtypes")
	public static byte[] decrypt(PrivateKey privateKey, byte[] encryptedMessage)
			throws Exception {
		CMSEnvelopedData ed = new CMSEnvelopedData(encryptedMessage);

		RecipientInformationStore recipients = ed.getRecipientInfos();
		Collection c = recipients.getRecipients();
		Iterator it = c.iterator();
		byte[] recData = (byte[]) null;
		if (it.hasNext()) {
			RecipientInformation recipient = (RecipientInformation) it.next();
			Security.addProvider(new BouncyCastleProvider());
			recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(
					privateKey).setProvider("BC"));

		}

		return recData;
	}
}
