package edu.huji.cs.netutils.build;

import edu.huji.cs.netutils.parse.IPPacketType;

/**
 * 
 * 
 * @author roni bar-yanai
 *
 */
public enum L4Type
{
	TCP,
	UDP,
	ICMP;
	
	static int L4toHexVal(L4Type type)
	{
		switch(type)
		{
		case TCP:
			return IPPacketType.TCP;
		case UDP:
			return IPPacketType.UDP;
		case ICMP:
			return IPPacketType.ICMP;
		default:
			throw new IllegalArgumentException("Unsupported value:"+type);
		}
	}

}
