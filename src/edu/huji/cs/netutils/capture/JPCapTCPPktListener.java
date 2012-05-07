package edu.huji.cs.netutils.capture;

import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Packet;
import edu.huji.cs.netutils.parse.TCPPacket;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;

/**
 * abstract TCP packet listener.
 * 
 * will filter only tcp packets.
 * just implement the process packet method.
 * 
 * @author roni bar-yanai
 *
 */
public abstract class JPCapTCPPktListener implements JPCapListener
{

	/**
	 * if the packet is tcp then will call the process method.
	 */
	public void processPacket(byte[] thePacket)
	{
		try
		{
			// check if ip (not arp or other none ip)
			if (EthernetFrame.statIsIpv4Packet(thePacket))
			{
				// check if tcp
				if (IPv4Packet.getIpProtocolType(thePacket) == IPPacketType.TCP)
				{
					processPacket((TCPPacketIpv4)IPv4Packet.getPacket(thePacket));
				}
			}
		}
		catch (RuntimeException e)
		{
			e.printStackTrace();
		}
	}
	
	/**
	 * The method will be called on each tcp packet that passed the filter.
	 * @param thePkt
	 */
	public abstract void processPacket(TCPPacketIpv4 thePkt);
}
