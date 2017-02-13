package tools.pki.gbay.crypto.texts;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import tools.pki.gbay.errors.CryptoException;

public interface SignedTextInterface {

	public abstract EncodedTextInterface toBase64();

	/**
	 * Signed value is the none-encoded signature
	 * @return the signedVal
	 */
	public abstract byte[] getSignedVal();

	/**
	 * @param signedVal the signedVal to set
	 */
	public abstract void setSignedVal(byte[] signedVal);

	/**
	 * @return the originalText
	 */
	public abstract PlainText getOriginalText();

	/**
	 * @param originalText the originalText to set
	 */
	public abstract void setOriginalText(PlainText originalText);


	/**
	 * @return the signerPublicKey
	 */
	public abstract List<X509Certificate> getSignerPublicKey();

	/**
	 * @param signerPublicKey the signerPublicKey to set
	 */
	public abstract void setSignerPublicKey(List<X509Certificate> signerPublicKey);

}