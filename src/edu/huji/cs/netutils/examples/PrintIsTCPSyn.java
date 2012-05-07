package edu.huji.cs.netutils.examples;

import edu.huji.cs.netutils.capture.JPCapListener;
import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Packet;
import edu.huji.cs.netutils.parse.TCPPacket;

/**
 * Example of Syn Listener
 * 
 * @author roni bar-yanai
 *
 */
public class PrintIsTCPSyn implements JPCapListener
{

	@Override
	public void processPacket(byte[] thePacket)
	{
		// first we check if this frame carries IP packet
		if(EthernetFrame.statIsIpv4Packet(thePacket))
		{
			// we check the protocol type is TCP
			if(IPv4Packet.getIpProtocolType(thePacket) == IPPacketType.TCP)
			{
				TCPPacket tcpPkt = new TCPPacket(thePacket);
				System.out.println("TCP segment payload length:"+tcpPkt.getPayloadDataLength());
			}
		}
		
	}

}
