package edu.huji.cs.netutils.inject.impl;

/**
 * Data structure for internal use.
 * The structure holds the key (int) which uniquely identifies
 * libnet instance (in c layer).   
 * 
 * (this is a code duplication. jpcap and jinject were two separate projects
 *  . we can live with that).
 * @author roni bar-yanai
 */
public class JInjectKey
{
	protected static final int JCAP_NO_KEY = -1;
	
	int myKey = JCAP_NO_KEY;
	
	/**
	 * create new key
	 * @param theKey
	 */
	public JInjectKey(int theKey)
	{
		myKey = theKey;
	}
	
	public int getKeyAsInt()
	{
		return myKey;
	}
	
	public String getAsString()
	{
		return "key:"+myKey;
	}
}
