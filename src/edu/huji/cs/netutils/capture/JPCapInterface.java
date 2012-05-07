package edu.huji.cs.netutils.capture;

/**
 * Data structure for holding interface information. 
 * Information includes:
 * IP and Name of the interface.
 * 
 * @author rbaryana
 */
public class JPCapInterface
{
	private String myName = null;
	private String myIp = null;
	
	/**
	 * @param theIp - the ip as a readable string (x.x.x.x)
	 * @param theName - the internal name of the interface
	 * @see JPCap
	 */
	protected JPCapInterface(String theIp, String theName)
	{
		myIp = theIp;
		myName = theName;
	}
	
	/**
	 * @return the interface ip
	 */
	public String getIp()
	{
		return myIp;
	}
	
	/**
	 * @return the interface name.
	 */
	public String getName()
	{
		return myName;
	}
	
	/**
	 *  (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString()
	{
		return "Name: "+myName+"\nAddress: "+myIp+"\n";
	}
	
	

}
