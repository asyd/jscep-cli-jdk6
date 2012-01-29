/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.opencsi.jscepcli;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 *
 * @author asyd
 */
public class KeyManager {

    public KeyPair createRSA() {
        KeyPairGenerator kpg;
        KeyPair kp = null;
        
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            kp = kpg.genKeyPair();
            
        } catch (Exception e) {
            
        }

        return kp;
    }
}
