package com.opencsi.jscepcli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
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
import org.jscep.CertificateVerificationCallback;
import org.jscep.client.Client;
import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.Transaction;

/**
 *
 * @author asyd
 */
public class App {

    AppParameters params;

    public void setParams(AppParameters params) {
        this.params = params;
    }

    public void scepCLI() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyManager km = new KeyManager();
        CertUtil certutil = new CertUtil();

        KeyPair kp = km.createRSA(params.getKeySize());

        X509Certificate cert = certutil.createSelfSignedCertificate(kp, params.getDn());
        CertificationRequest request = certutil.createCertificationRequest(kp, params.getDn(), params.getChallenge());
        CallbackHandler handler = new ConsoleCallbackHandler();
        URL serverURL = new URL(params.getUrl());

        try {
            if (params.getCsrFile() != null) {
                saveToFile(params.getCsrFile(), request.getDEREncoded());
            }

            Client client = new Client(serverURL,
                    cert,
                    kp.getPrivate(),
                    handler,
                    params.getCaIdentifier());

            client.getCaCertificate();
            EnrolmentTransaction tx = client.enrol(request);
            Transaction.State response = tx.send();

            if (response == Transaction.State.CERT_ISSUED) {
                System.out.println("Certificate issued");
                saveToFile(params.getKeyFile(), kp.getPrivate().getEncoded());
                CertStore store = tx.getCertStore();
                Collection<? extends Certificate> certs = store.getCertificates(null);
                Iterator it = certs.iterator();
                while (it.hasNext()) {
                    X509Certificate certificate = (X509Certificate) it.next();
                    if(certificate.getBasicConstraints() != -1) {
                        saveToFile(params.getCaCertificateFile(), certificate.getEncoded());
                    } else {
                        saveToFile(params.getCertificateFile(), certificate.getEncoded());
                    }
                }
            } else {
                System.err.println("Unknow error"  + response);
            }
        } catch (IOException e) {
            System.err.print(e.getMessage());
            if (e.getMessage().contains("400")) {
                System.err.println(". Probably a template issue, look at PKI log");
            } else if(e.getMessage().contains("404")) {
                System.err.println(". Invalid URL or CA identifier");
            } else if(e.getMessage().contains("401")) {
                System.err.println(". Probably EJBCA invalid entity status");
            }

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public void saveToFile(String filename, byte[] data) throws IOException {
        BufferedOutputStream oout = null;

        try {
            oout = new BufferedOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
            oout.write(data);
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        } finally {
            oout.close();
        }

    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "none");
        App app = new App();
        AppParameters params = new AppParameters();
        JCommander jcmd = new JCommander(params);
        
        try {
            jcmd.parse(args);

            app.setParams(params);
            app.scepCLI();
        } catch (ParameterException e) {
            jcmd.usage();
        }
    }

    private static class ConsoleCallbackHandler implements CallbackHandler {

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
