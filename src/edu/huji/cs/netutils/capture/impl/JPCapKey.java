package edu.huji.cs.netutils.capture.impl;

/**
 * For internal implementation.
 * Each pcap listener in the c environment will be uniqely
 * identified by a key.
 * 
 * @author roni bar-yanai
 *
 */
public class JPCapKey
{
	// mark no key constant
	protected static final int JCAP_NO_KEY = -1;
	
	private int myKey = JCAP_NO_KEY;
	
	/**
	 * create new key
	 * @param theKey
	 */
	public JPCapKey(int theKey)
	{
		myKey = theKey;
	}
	
	/**
	 * @return key as int.
	 */
	public int getKeyAsInt()
	{
		return myKey;
	}
	
	public String getAsString()
	{
		return "key:"+myKey;
	}
}
