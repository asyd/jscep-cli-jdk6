package com.opencsi.jscepcli;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.jscep.client.CertificateVerificationCallback;
import org.jscep.client.Client;
import org.jscep.client.EnrollmentResponse;
import org.jscep.transaction.Transaction;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.varia.NullAppender;

/**
 *
 * @author asyd
 */
public class App {

    AppParameters params;
//    KeyPair kp;
//    CertUtil certutil;

    public void setParams(AppParameters params) {
        this.params = params;
    }

    public App() {
    }

    public void scepCLI() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyManager km = new KeyManager();
        CertUtil certutil = new CertUtil();

        KeyPair kp = km.createRSA(params.getKeySize());

        X509Certificate cert = certutil.createSelfSignedCertificate(kp, params.getDn());
        PKCS10CertificationRequest request = certutil.createCertificationRequest(kp, params.getDn(), params.getChallenge());
        CallbackHandler handler = new ConsoleCallbackHandler();
        URL serverURL = new URL(params.getUrl());

        try {
            if (params.getCsrFile() != null) {
                saveToPEM(params.getCsrFile(), request);
            }

            Client client = new Client(serverURL, handler);

            client.getCaCertificate();

            EnrollmentResponse response = client.enrol(cert, kp.getPrivate(), request, params.getCaIdentifier());

            /*
             * handle asynchronous response
             */
            while (response.isPending()) {
                Thread.currentThread().sleep(1000);
                System.out.println("CERT_REQ_PENDING, wait 1 second");
                response = client.poll(cert, kp.getPrivate(),
                                       cert.getSubjectX500Principal(),
                                       response.getTransactionId(),
                                       params.getCaIdentifier());
            }

            if (response.isSuccess()) {
                X509Certificate clientCertificate = null;

                try {
                    saveToPEM(params.getKeyFile(), kp.getPrivate());
                    CertStore store = response.getCertStore();
                    Collection<? extends Certificate> certs = store.getCertificates(null);
                    Iterator it = certs.iterator();
                    while (it.hasNext()) {
                        X509Certificate certificate = (X509Certificate) it.next();
                        if (certificate.getBasicConstraints() != -1) {
                            saveToPEM(params.getCaCertificateFile(), certificate);
                        } else {
                            clientCertificate = certificate;
                            saveToPEM(params.getCertificateFile(), certificate);
                        }
                    }
                    System.out.println("Certificate issued");

                    try {
                        saveToPEM(params.getCrlFile(), client.getRevocationList(clientCertificate,
                                                                                kp.getPrivate(),
                                                                                clientCertificate.getIssuerX500Principal(),
                                                                                clientCertificate.getSerialNumber()));
                    } catch (Exception e) {
                        System.err.println("Exception while saving CRL");
                        if(params.getVerbose()) {
                            e.printStackTrace();
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Exception while saving files: " + e);
                    if(params.getVerbose()) {
                        e.printStackTrace();
                    }
                }
            } else {
                System.err.println("Failure response: " + response.getFailInfo());
            }
        } catch (IOException e) {
            if(params.getVerbose()) {
                e.printStackTrace();
            }

            System.err.println(e.getMessage());
            if (e.getMessage().contains("400")) {
                System.err.println(". Probably a template issue, look at PKI log");
            } else if (e.getMessage().contains("404")) {
                System.err.println(". Invalid URL or CA identifier");
            } else if (e.getMessage().contains("401")) {
                System.err.println(". Probably EJBCA invalid entity status");
            }

        } catch (Exception e) {
            System.out.println(e);
            if(params.getVerbose()) {
                e.printStackTrace();
            }
        }
    }

    public void saveToPEM(String filename, Object data) throws IOException {
        PEMWriter writer = new PEMWriter(new FileWriter(new File(filename)));
        writer.writeObject(data);
        writer.close();
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "none");

        App app = new App();
        AppParameters params = new AppParameters();
        JCommander jcmd = new JCommander(params);

        try {
            jcmd.parse(args);

            app.setParams(params);

            Logger root = Logger.getRootLogger();
            if(params.getVerbose()) {
                root.addAppender(new ConsoleAppender(
                    new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN)));
            } else {
                root.addAppender(new NullAppender());
            }

            app.scepCLI();
        } catch (ParameterException e) {
            jcmd.usage();
        }
    }

    private static class ConsoleCallbackHandler implements CallbackHandler {

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof CertificateVerificationCallback) {
                    CertificateVerificationCallback callback = (CertificateVerificationCallback) callbacks[i];
                    callback.setVerified(true);
                } else {
                    throw new UnsupportedCallbackException(callbacks[i]);
                }
            }
        }
    }
}
