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
    
    
}
