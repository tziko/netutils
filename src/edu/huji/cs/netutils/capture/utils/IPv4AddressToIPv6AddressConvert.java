package edu.huji.cs.netutils.capture.utils;

import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.IPv6Address;

/**
 * Used when converting capture files from IPv4 to IPv6.
 * 
 * @author roni bar-yanai
 *
 */
public interface IPv4AddressToIPv6AddressConvert
{
	public IPv6Address convert(IPv4Address theIPaddr);
}
