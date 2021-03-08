/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

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

        X500Name principal = new X500Name(dn);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(principal, serial, now, now, principal, spki);
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider()).build(kp.getPrivate());
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        return (X509Certificate) CertificateFactory.getInstance("X.509", new BouncyCastleProvider()).generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));      
    }

    public PKCS10CertificationRequest createCertificationRequest(KeyPair kp, String dn, String password) {
        PKCS10CertificationRequest request = null;

        try {
            JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(dn), kp.getPublic());
            if (password != null) {
                DERPrintableString passwordDer = new DERPrintableString(password);
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, passwordDer);
            }

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
            request = builder.build(signerBuilder.build(kp.getPrivate()));
        } catch (Exception e) {
            System.err.println("Exception:" + e);
        }
        return request;
    }

    public X500Principal parseDN(String dn) {
        return new X500Principal(dn);
    }

}
