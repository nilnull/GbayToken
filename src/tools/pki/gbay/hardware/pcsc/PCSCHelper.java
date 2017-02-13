/**
 *	GBay Hardware Devices - a token and smart card managment solution (library)
 *	Copyright (c) 2014 Araz Farhang - www.pki.tools
 *
 *	

 *	
 *	This API is intended to be used by other aegis applications
 *
 *	This program is distributed in the hope that it will be useful. *

 *
 */
/*
 * $Header: /cvsroot/GBay Hardware Devices/GBay Hardware Devices/src/java/core/it/trento/comune/GBay Hardware Devices/pcsc/PCSCHelper.java,v 1.1 2004/12/27 11:14:32 resoli Exp $
 * $Date: 2004/12/27 11:14:32 $
 */

package tools.pki.gbay.hardware.pcsc;


import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import java.util.Vector;



/**
 * A java class for detecting SmartCard tokens and readers via PCSC. 
 * 
 * @author Araz Farhang
 */
public class PCSCHelper {
    private Hashtable cardInfos = new Hashtable();
    private Hashtable cards = new Hashtable();

    private String deviceListFile = "sc.properties";
    

    /** The context to the PCSC ResourceManager */
    private int context = 0;

    /** The state of this card terminal. */
    private boolean closed;

    /** Is a card inserted currently? */
    private boolean cardInserted;

    /** The cardHandle */
    private int cardHandle = 0;

    /* states returned by SCardGetStatusChange */
    private static final int SCARD_STATE_MUTE = 0x200;

    private static final int SCARD_STATE_PRESENT = 0x020;

    /** The <tt>ATR</tt> of the presently inserted card. */
    private byte[] cachedATR;

    private String type = null;

    private String[] readers = null;




    public PCSCHelper(boolean loadLib) {

            System.out.println("connect to PCSC 1.0 resource manager");


            this.type = "PCSC10";


            System.out.println("Driver initialized");

            loadProperties();


        /* add one slot */
        //this.addSlots(1);
    }

    private void loadProperties() {

        System.out.println("Loading properties...");

        Properties prop = new Properties();
        InputStream propertyStream;

        propertyStream = this.getClass().getResourceAsStream(deviceListFile);

        if (propertyStream != null) {
            try {
                prop.load(propertyStream);
            } catch (IOException e2) {
                System.out.println(e2);
            }
            //prop.list(System.out);
        }

        Iterator i = prop.keySet().iterator();

        String currKey = null;

        int index = 0;
        int pos = -1;
        String attribute = null;
        String value = null;

        //loading propertis in a vector of CardInfo
        Vector<CardInfo> v = new Vector<CardInfo>();
        CardInfo ci = null;
        while (i.hasNext()) {
            currKey = (String) i.next();
            pos = currKey.indexOf(".");
            index = Integer.parseInt(currKey.substring(0, pos));
            attribute = currKey.substring(pos + 1);
            value = (String) prop.get(currKey);
            value = "atr".equals(attribute) ? value.toUpperCase() : value;

            while (index > v.size()) {
                ci = new CardInfo();
                v.addElement(ci);
            }
            ci = (CardInfo) v.get(index - 1);
            ci.addProperty(attribute, value);
        }

        //coverting vector to Hashtable (keyed by ATR)
        i = v.iterator();
        while (i.hasNext()) {
            ci = (CardInfo) i.next();
            this.cardInfos.put(ci.getProperty("atr"), ci);
        }

    }

    public static void main(String[] args) {

        PCSCHelper a = new PCSCHelper(true);
        a.findCards();
        System.exit(0);

    }

    public List<CardInfo> findCards() {
        
        ArrayList<CardInfo> cards = new ArrayList<CardInfo>();
        
        try {
            int numReaders = getReaders().length;
            
            System.out.println("Found " + numReaders + " readers.");

            String currReader = null;
            for (int i = 0; i < getReaders().length; i++) {
                currReader = getReaders()[i];
                System.out.println("\nChecking card in reader '"
                        + currReader + "'.");
                if (false) {
                    System.out.println("Card is present in reader '"
                            + currReader + "' , ATR String follows:");
                    System.out.println("ATR: " + formatATR(cachedATR, " "));

                    CardInfo ci = (CardInfo) getCardInfos().get(
                            formatATR(cachedATR, ""));
                    
                    if (ci != null) {
                        cards.add(ci);
                        
                        System.out
                                .println("\nInformations found for this card:");
                        System.out.println("Description:\t"
                                + ci.getProperty("description"));
                        System.out.println("Manufacturer:\t"
                                + ci.getProperty("manufacturer"));
                        System.out.println("ATR:\t\t" + ci.getProperty("atr"));
                        System.out.println("Criptoki:\t"
                                + ci.getProperty("lib"));
                    }

                } else {
                    System.out.println("No card in reader '" + currReader
                            + "'!");
                }
            }

        } catch (Exception e) {
            System.out.println(e);
        }
        return cards;
    }

    public String formatATR(byte[] atr, String byteSeparator) {
        int n, x;
        String w = new String();
        String s = new String();

        for (n = 0; n < atr.length; n++) {
            x = (int) (0x000000FF & atr[n]);
            w = Integer.toHexString(x).toUpperCase();
            if (w.length() == 1)
                w = "0" + w;
            s = s + w + ((n + 1 == atr.length) ? "" : byteSeparator);
        } // for
        return s;
    }

    /**
     * Check whether there is a smart card present.
     * 
     * @param name 
     *            Name of the reader to check.
     * @return True if there is a smart card inserted in the card terminals
     *         slot.
     */

    /**
     * @return Returns the readers.
     */
    public String[] getReaders() {
        return readers;
    }

    /**
     * @return Returns the cardInfos.
     */
    public Hashtable getCardInfos() {
        return cardInfos;
    }
}