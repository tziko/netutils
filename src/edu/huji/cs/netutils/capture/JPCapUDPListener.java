package edu.huji.cs.netutils.capture;

import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Packet;
import edu.huji.cs.netutils.parse.UDPPacket;

/**
 * will process only udp packets.
 * 
 * implement:
 * public abstract void processPacket(UDPPacket pkt);
 * 
 * @author roni bar-yanai
 *
 */
public abstract class JPCapUDPListener implements JPCapListener
{
	/**
	 * (non-Javadoc)
	 * @see edu.huji.cs.netutils.capture.JPCapListener#processPacket(byte[])
	 */
	public void processPacket(byte[] thePacket)
	{
		try
		{
			// check if ip packet (not arp or other none ip packet)
			if (EthernetFrame.statIsIpv4Packet(thePacket))
			{
				// check if udp
				if (IPv4Packet.getIpProtocolType(thePacket) == IPPacketType.UDP)
				{
					processPacket((UDPPacket)IPv4Packet.getPacket(thePacket));
				}
			}
		}
		catch (RuntimeException e)
		{
			e.printStackTrace();
		}
	}
	
	/**
	 * method will be called on each udp packet that have passed the filter 
	 * (on the listening interface).
	 * @param pkt
	 */
	public abstract void processPacket(UDPPacket pkt);
}
