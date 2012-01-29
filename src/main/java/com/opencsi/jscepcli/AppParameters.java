/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import com.beust.jcommander.Parameter;

/**
 *
 * @author asyd
 */
public class AppParameters {
    
    @Parameter(names = "--dn", description = "Subject DN to request", required = true)
    private String dn;
    
    @Parameter(names = "--keySize", description = "Size of key, if you want more than 2048, you need the JCE")
    private Integer keySize = 2048;
    
    @Parameter(names = "--algorithm", description = "BouncyCastle signature algorithm to use")
    private String algorithm = "SHA1";
    
    @Parameter(names = "--challenge", description = "Challenge password (EJBCA entity password)", required=true )
    private String challenge;
    
    @Parameter(names = "--url", description = "SCEP URL (for EJBCA, use http://<hostname>:<port>//ejbca/publicweb/apply/scep/pkiclient.exe", required=true)
    private String url;
    
    @Parameter(names = "--certificate-file", description = "Certificate output file")
    private String certificateFile = "cert.pem";
    
    @Parameter(names = "--ca-certificate-file", description = "CACert output file")
    private String caCertificateFile = "cacert.pem";
    
    @Parameter(names = "--csr-file", description = "CSR output file")
    private String csrFile;
    
    @Parameter(names = "--key-file", description = "Private key output file")
    private String keyFile = "privkey.pem";
    
    @Parameter(names = "--ca-identifier", description = "CA identifier")
    private String caIdentifier = "AdminCA1";

    /**
     * @return the dn
     */
    public String getDn() {
        return dn;
    }

    /**
     * @return the keySize
     */
    public Integer getKeySize() {
        return keySize;
    }

    /**
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * @return the challenge
     */
    public String getChallenge() {
        return challenge;
    }

    /**
     * @return the url
     */
    public String getUrl() {
        return url;
    }

    /**
     * @return the certificateFile
     */
    public String getCertificateFile() {
        return certificateFile;
    }

    /**
     * @return the caCertificateFile
     */
    public String getCaCertificateFile() {
        return caCertificateFile;
    }

    /**
     * @return the csrFile
     */
    public String getCsrFile() {
        return csrFile;
    }

    /**
     * @return the keyFile
     */
    public String getKeyFile() {
        return keyFile;
    }

    /**
     * @return the caIdentiifier
     */
    public String getCaIdentifier() {
        return caIdentifier;
    }
}
