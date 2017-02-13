/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package tools.pki.gbay.hardware.pkcs11;

import java.security.cert.X509Certificate;
import java.util.Set;

/**
 *
 * @author farhang
 */
public interface CertificateSelectorInterface {

    public int SelectCert(Set<X509Certificate> certs);
    
}
