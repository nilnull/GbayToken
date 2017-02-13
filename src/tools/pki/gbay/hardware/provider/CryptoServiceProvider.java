package tools.pki.gbay.hardware.provider;

import org.bouncycastle.cms.CMSSignedData;

import tools.pki.gbay.crypto.texts.PlainText;
import tools.pki.gbay.crypto.texts.SignedText;
import tools.pki.gbay.errors.CryptoException;

public interface CryptoServiceProvider {

	CMSSignedData getSignedData() throws CryptoException;

	SignedText sign(PlainText text) throws CryptoException;

}
