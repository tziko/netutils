package edu.huji.cs.netutils.capture;

import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.ICMPPacket;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Packet;

/**
 * Class for implementing icmp listener. 
 * 
 * the abstract method processPacket(ICMPPacket thePkt) should be implemented.
 * 
 * @author roni bar-yanai
 */
public abstract class JPCapICMPListener implements JPCapListener
{

	private boolean _verbose = false; 
	
	/**
	 * if set to true then will print exception to screen.
	 * 
	 * @param enable
	 */
	public void setVerbose(boolean enable)
	{
		_verbose = enable;
	}
	
	/**
	 * if the packet is icmp then will call the process method.
	 */
	final public void processPacket(byte[] thePacket)
	{
		try
		{
			if (EthernetFrame.statIsIpv4Packet(thePacket))
			{
				if (IPv4Packet.getIpProtocolType(thePacket) == IPPacketType.ICMP)
				{
					processPacket((ICMPPacket)IPv4Packet.getPacket(thePacket));
				}
			}
		}
		catch (Exception e)
		{
			if (_verbose)
			e.printStackTrace();
		}
	}
	
	/**
	 * The method will be called on each icmp packet that passed the filter.
	 * @param thePkt
	 */
	public abstract void processPacket(ICMPPacket thePkt);


}
