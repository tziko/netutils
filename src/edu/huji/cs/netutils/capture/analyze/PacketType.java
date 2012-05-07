package edu.huji.cs.netutils.capture.analyze;


/**
 * Packet types for analyze.
 * We split them into IP protocols, ARPs and non IPS.
 * Basically we are interested in TCP and UDP.
 * 
 * 
 * @author roni bar-yanai
 *
 */
public enum PacketType
{
	TCP,
	UDP,
	ICMP,
	IPFragment,
	ARP,
	NONIP,
	OTHER;
}
