/*
 * GBAy Crypto API
 * Copyright (c) 2014, PKI.Tools All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package tools.pki.gbay.crypto.texts;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import tools.pki.gbay.errors.CryptoError;
import tools.pki.gbay.errors.CryptoException;
import tools.pki.gbay.errors.GlobalErrorCode;
import tools.pki.gbay.hardware.provider.CryptoServiceProvider;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

// TODO: Auto-generated Javadoc
/**
 * A signed text which contains signed values and can be verified .
 *
 * @author Araz Farhang
 */
public class SignedText extends PlainText implements SignedTextInterface {
	
	/** The signer public key. */
	List<X509Certificate> signerPublicKey;
	
	/** The signed data. */
	CMSSignedData signedData;

	/** The signed val. */
	byte[] signedVal;
	
	/** The original text. */
	PlainText originalText;
	

	
	/** The attached. */
	boolean attached;
	

	

	/**
	 * The Constructor.
	 *
	 * @param originaltext the originaltext
	 * @param signedValue the signed value
	 */
	public SignedText(String originaltext , byte[] signedValue) {
		super(signedValue);
		signedVal = signedValue;
		this.originalText = new PlainText(originaltext);
		if (originaltext!= null)
			this.attached = true;
		else
			this.attached = false;
	}

	/**
	 * The Constructor.
	 *
	 * @param originaltext the originaltext
	 * @param signedValue the signed value
	 */
	public SignedText(byte[] originaltext , byte[] signedValue) {
		super(signedValue);	
		signedVal = signedValue;
		this.originalText = new PlainText(originaltext);
		if (originaltext!= null)
			this.attached = true;
		else
			this.attached = false;
	}

	/**
	 * The Constructor.
	 *
	 * @param originaltext the originaltext
	 * @param data the data
	 * @param attached the attached
	 * @throws IOException the IO exception
	 */
	public SignedText(String originaltext , CMSSignedData data , boolean attached) throws IOException {
		super(data.getEncoded());
		signedVal = data.getEncoded();
		this.originalText = new PlainText(originaltext);
		this.attached = attached;
	}

    /**
     * The Constructor.
     *
     * @param originaltext the originaltext
     * @param signedValue the signed value
     * @param trustedIssuer the trusted issuer
     * @param crl the crl
     * @param attached the attached
     */
    public SignedText(String originaltext , byte[] signedValue ,  boolean attached) {
    	super(signedValue);
    	this.signedVal = signedValue;
    	this.originalText = new PlainText(originaltext);
    	this.attached = attached;
    }

    /* (non-Javadoc)
     * @see tools.pki.gbay.crypto.texts.BasicText#toBase64()
     */
    @Override
	public EncodedTextInterface toBase64(){
    	return new Base64(this.signedVal);
    }

    
    
    /**
     * The Constructor.
     *
     * @param originalText the original text
     * @param signedVal the signed val
     * @param signerPublicKey the signer public key
     */
    public SignedText(String originalText , byte[] signedVal, List<X509Certificate> signerPublicKey) {
		super(signedVal);
		this.signerPublicKey = signerPublicKey;
		this.signedVal = signedVal;
		this.originalText = new PlainText(originalText);
	}
    
    /**
     * Checks if is attached.
     *
     * @param signedVal the signed val
     * @return true, if checks if is attached
     * @throws CMSException the CMS exception
     */
    public static boolean isAttached(byte[] signedVal) throws CMSException {
    	CMSSignedData signedData = new CMSSignedData(signedVal); 
		CMSProcessable processable = signedData.getSignedContent();
		if (processable == null){
			return false;
		}
		else{
			return true;
		}
    }
    
    /**
     * Detect attached.
     *
     * @return the CMS signed data
     * @throws CMSException the CMS exception
     */
    public CMSSignedData detectAttached() throws CMSException{
    	CMSSignedData signedData = new CMSSignedData(signedVal); 
		CMSProcessable processable = signedData.getSignedContent();
		if (processable == null){
			System.out.println("Not attached");
			attached = false;
		}
		else{
			System.out.println("Is attached");
			attached = true;
		}
		return signedData;
    }

    
    /**
     * Extract certificate and check if signature is attached or not.
     *
     * @throws CryptoException the gbay crypto exception
     */
    public void ExtractCertificate() throws CryptoException{
    		signerPublicKey = new ArrayList<X509Certificate>();
    	try {
    			CMSSignedData cms = detectAttached();
    			Store store = cms.getCertificates();
    			SignerInformationStore signers = cms.getSignerInfos();
    			Collection c = signers.getSigners();
    			Iterator it = c.iterator();
    			while (it.hasNext()) {
    				SignerInformation signer = (SignerInformation) it.next();
    				Collection certCollection = store.getMatches(signer.getSID());
    				Iterator certIt = certCollection.iterator();
    				X509CertificateHolder certHolder = (X509CertificateHolder) certIt .next();
    				X509Certificate currentCert = new JcaX509CertificateConverter().setProvider(
    						"BC").getCertificate(
    						certHolder);
    				signerPublicKey.add(currentCert);
    				
    			}
    		} catch (CertificateException e) {
    			e.printStackTrace();
    			throw new CryptoException(
    					new CryptoError(GlobalErrorCode.CERT_INVALID_FORMAT));
    		
			} catch (CMSException e) {
				throw new CryptoException(
    					new CryptoError(GlobalErrorCode.SIG_INVALID));
    		
			}
    	
    }
	
	/**
	 * The Constructor.
	 */
	public SignedText() {
		super();
	}


	

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#getSignedVal()
	 */
	@Override
	public byte[] getSignedVal() {
		return signedVal;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#setSignedVal(byte[])
	 */
	@Override
	public void setSignedVal(byte[] signedVal) {
		this.byteRep = signedVal;
		this.signedVal = signedVal;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#getOriginalText()
	 */
	@Override
	public PlainText getOriginalText() {
		return originalText;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#setOriginalText(tools.pki.gbay.crypto.texts.PlainText)
	 */
	@Override
	public void setOriginalText(PlainText originalText) {
		this.originalText = originalText;
	}
    

	



	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#getSignerPublicKey()
	 */
	@Override
	public List<X509Certificate> getSignerPublicKey() {
		return signerPublicKey;
	}

	/* (non-Javadoc)
	 * @see tools.pki.gbay.crypto.texts.SignedTextInterface#setSignerPublicKey(tools.pki.gbay.crypto.keys.PublicKey)
	 */
	@Override
	public void setSignerPublicKey(List<X509Certificate> signerPublicKey) {
		this.signerPublicKey = signerPublicKey;
	}

	/**
	 * Checks if is attached.
	 *
	 * @return the isEncapsulated
	 */
	public boolean isAttached() {
		return attached;
	}

	/**
	 * Sets the attached.
	 *
	 * @param isEncapsulated the isEncapsulated to set
	 */
	public void setAttached(boolean isEncapsulated) {
		this.attached = isEncapsulated;
	}


 

}
