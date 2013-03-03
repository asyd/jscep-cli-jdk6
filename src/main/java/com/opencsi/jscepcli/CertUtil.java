/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 *
 * @author asyd
 */
public class CertUtil {

    /*
     * @description This method create a self signed certificated
     */
    public X509Certificate createSelfSignedCertificate(KeyPair kp, String dn) throws Exception {
        Date now = new Date();
        BigInteger serial = new BigInteger("1");

        X500Principal principal = new X500Principal(dn);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setIssuerDN(principal);
        certGen.setSubjectDN(principal);
        certGen.setSerialNumber(serial);
        certGen.setNotBefore(now);
        certGen.setNotAfter(now);
        certGen.setPublicKey(kp.getPublic());
        certGen.setSignatureAlgorithm("SHA1withRSA");


        return certGen.generate(kp.getPrivate(), "BC");
    }

    public PKCS10CertificationRequest createCertificationRequest(KeyPair kp, String dn, String password) {
        PKCS10CertificationRequest request = null;

        try {
            JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(dn), kp.getPublic());
            DERPrintableString passwordDer = new DERPrintableString(password);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, passwordDer);

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
            request = builder.build(signerBuilder.build(kp.getPrivate()));
/*
            request = new PKCS10CertificationRequest("SHA1withRSA",
                    parseDN(dn),
                    kp.getPublic(),
                    attributes,
                    kp.getPrivate());
*/

        } catch (Exception e) {
            System.err.println("Exception:" + e);
        }
        return request;
    }

    public X500Principal parseDN(String dn) {
        return new X500Principal(dn);
    }

}
