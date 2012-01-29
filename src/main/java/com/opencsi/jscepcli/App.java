/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import com.beust.jcommander.Parameter;
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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.jscep.CertificateVerificationCallback;
import org.jscep.client.Client;
import org.jscep.transaction.EnrolmentTransaction;
import org.jscep.transaction.Transaction;

/**
 *
 * @author asyd
 */
public class App {
    
    @Parameter(names = "--dn", description = "Subject DN")
    private String dn;

    /**
     * @param args the command line arguments
     */
    public void scepCLI() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyManager km = new KeyManager();
        CertUtil certutil = new CertUtil();
        
        KeyPair kp = km.createRSA();

        X509Certificate cert = certutil.createSelfSignedCertificate(kp, dn);


        CertificationRequest request = certutil.createCertificationRequest(kp, dn, "foo123");

        CallbackHandler handler = new ConsoleCallbackHandler();


        URL serverURL = new URL("https://ritsuko.asyd.net:8442/ejbca/publicweb/apply/scep/pkiclient.exe");

        try {
            saveToFile("/tmp/csr.der", request.getDEREncoded());
            System.out.println("data: " + PKCSObjectIdentifiers.data.toString());
            Client client = new Client(serverURL,
                    cert,
                    kp.getPrivate(),
                    handler,
                    "AdminCA");

            client.getCaCertificate();
            EnrolmentTransaction tx = client.enrol(request);
            Transaction.State response = tx.send();

            if (response == Transaction.State.CERT_ISSUED) {
                System.out.println("Certificate issued");
                CertStore store = tx.getCertStore();
                Collection<? extends Certificate> certs = store.getCertificates(null);
                System.out.println("size: " + certs.size());
                Iterator it = certs.iterator();
                Integer i = 0;
                while(it.hasNext()) {
                    X509Certificate certificate = (X509Certificate) it.next();
                    saveToFile("/tmp/cert" + i, certificate.getEncoded());
                    i++;
                }
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public void saveToFile(String filename, byte[] data) throws IOException {
        BufferedOutputStream oout = null;

        try {
            oout = new BufferedOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
            oout.write(data, 0, data.length);
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        } finally {
            oout.close();
        }

    }

    public static void main(String[] args) {
        // TODO code application logic here

        System.setProperty("javax.net.debug", "none");
        App main = new App();
        try {
            main.scepCLI();
        } catch (Exception e) {
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
