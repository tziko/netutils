package edu.huji.cs.netutils.parse;

/**
 * Common interface for IPv6 and IPv4 addresses.
 * 
 * 
 * @author roni bar-yanai
 *
 */
public interface IPAddress
{
	public boolean isGreater(IPAddress ip2);
	
	public String getAsReadableString();
}
