/**
 *	GBay Hardware Devices - a token and smart card managment solution (library)
 *	Copyright (c) 2014 Araz Farhang - www.pki.tools
 *	
 *	This API is intended to be used by other aegis applications
 *
 *	This program is distributed in the hope that it will be useful.
 *	
 */

/*
 * $Date: 2004/12/27 11:14:32 $
 */
package tools.pki.gbay.hardware.pcsc;

import java.util.Hashtable;

/**
 * Stores informations about a card.
 * 
 * @author Araz Farhang
 *
 */

public class CardInfo {
    private Hashtable infos = new Hashtable();

    /**
     * Adds the given attribute with corresponding value.
     * 
     * @param attribute key for retrieving the information.
     * @param value information to store.
     */
    public void addProperty(String attribute, Object value) {
       System.err.println(attribute+"  | "+(String)value);
    	infos.put(attribute, value);
    }

    /**
     * Retrieves the value for the given attribute.
     * 
     * @param attribute key to search.
     * @return the value for the given attribute, <code>null</code> if not found.
     */
    public String getProperty(String attribute) {
        return (String) infos.get(attribute);
    }
    
    public String getDescription(){
    	return getProperty("description");
    }
    
    public String getLib(){
    	return getProperty("lib");
    }
    
    public String getATR(){
    	return getProperty("atr");
    }
    
    @Override
    public String toString() {
    	// TODO Auto-generated method stub
    	return getProperty("description");
    }

}