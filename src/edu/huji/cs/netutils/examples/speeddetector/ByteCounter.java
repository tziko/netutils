package edu.huji.cs.netutils.examples.speeddetector;

import java.text.DecimalFormat;

import edu.huji.cs.netutils.capture.JPCapListener;
import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.IPAddress;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Packet;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
import edu.huji.cs.netutils.parse.UDPPacketIpv4;

/**
 * The listener counts the total uploaded and downloaded bytes according
 * to protocol types.<br>
 * The listener will also calculate the rates provided that the update method is called
 * periodic.<br>
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class ByteCounter implements JPCapListener
{
	private IPAddress mySourceIp;
	
	// counters
	private long myTcpOutBytes = 0;
	private long myTcpInBytes = 0;
	private long myUdpOutBytes = 0;
	private long myUdpInBytes = 0;
	
	// last value is used for rates calculations.
	private long myLastTcpOutBytes = 0;
	private long myLastTcpInBytes = 0;
	private long myLastUdpOutBytes = 0;
	private long myLastUdpInBytes = 0;
	
	private float myLastTcpOutRate = 0;
	private float myLastTcpInRate = 0;
	private float myLastUdpOutRate = 0;
	private float myLastUdpInRate = 0;
	
	private long myLastTime = 0;
	
	/**
	 * create instance, the source IP is used to determine the direcitons
	 * of the packets.	
	 * @param theSurceIp
	 */
	public ByteCounter(IPAddress theSurceIp)
	{
		super();
		mySourceIp = theSurceIp;
	}

	@Override
	public void processPacket(byte[] thePacket)
	{
		synchronized(this)
		{
		// first we check if this frame carries IP packet
		if(EthernetFrame.statIsIpv4Packet(thePacket))
		{
			// we check the protocol type is TCP
			if(IPv4Packet.getIpProtocolType(thePacket) == IPPacketType.TCP)
			{
				// update counters according to the direction.
				TCPPacketIpv4 tcpPkt = new TCPPacketIpv4(thePacket);
				if(tcpPkt.getUnderlyingIPPacketBase().getSourceIP().equals(mySourceIp))
				{
					myTcpOutBytes+=thePacket.length;
				}
				else if(tcpPkt.getUnderlyingIPPacketBase().getDestinationIP().equals(mySourceIp))
				{
					myTcpInBytes+=thePacket.length;
				}
			}
			else if(IPv4Packet.getIpProtocolType(thePacket) == IPPacketType.UDP)
			{
				UDPPacketIpv4 udpPkt = new UDPPacketIpv4(thePacket);
				if(udpPkt.getUnderlyingIPPacketBase().getSourceIP().equals(mySourceIp))
				{
					myUdpOutBytes+=thePacket.length;
				}
				else if(udpPkt.getUnderlyingIPPacketBase().getDestinationIP().equals(mySourceIp))
				{
					myUdpInBytes+=thePacket.length;
				}
				
			}
		}
		}
	}
	
	@Override
	public String toString() {
		StringBuffer sbuff = new StringBuffer();
		DecimalFormat df = new DecimalFormat("#####.#");
		sbuff.append("Total TCP out bytes:"+myTcpOutBytes+"\n");
		sbuff.append("Total TCP in bytes :"+myTcpInBytes+"\n");
		sbuff.append("Total UDP out bytes:"+myUdpOutBytes+"\n");
		sbuff.append("Total UDP in bytes :"+myUdpInBytes+"\n");
		
		sbuff.append("TCP out bytes rate :"+df.format(myLastTcpOutRate/1024)+" kbits per second\n");
		sbuff.append("TCP in bytes rate  :"+df.format(myLastTcpInRate/1024)+" kbits per second\n");
		sbuff.append("UDP out bytes rate :"+df.format(myLastUdpOutRate/1024)+" kbits per second\n");
		sbuff.append("UDP in bytes rate  :"+df.format(myLastUdpInRate/1024)+" kbits per second\n");
		
		
		return sbuff.toString();
	}
	
	
	/**
	 * Update will update the rates. It should be called periodically.
	 * (filter is used to prevent rates jumping and crate more smooth results)
	 */
	public synchronized void update()
	{
		if(myLastTime == 0 )
		{
			myLastTcpOutBytes = myTcpOutBytes;
			myLastTcpInBytes = myTcpInBytes;
			myLastUdpOutBytes = myUdpOutBytes;
			myLastUdpInBytes = myUdpInBytes;
			myLastTime = System.currentTimeMillis();
			return;
		}
		
		float time = System.currentTimeMillis() - myLastTime;
		myLastTime = System.currentTimeMillis();
		System.out.println("time="+time);
		if(time == 0)
			return;
		
		myLastTcpOutRate = myLastTcpOutRate*0.6f + 1000*0.4f*((float)(myTcpOutBytes - myLastTcpOutBytes))/time;
		myLastTcpInRate = myLastTcpInRate*0.6f + 1000*0.4f*((float)(myTcpInBytes - myLastTcpInBytes))/time;
		myLastUdpOutRate = myLastUdpOutRate*0.6f + 1000*0.4f*((float)(myUdpOutBytes - myLastUdpOutBytes))/time;
		myLastUdpInRate = myLastUdpInRate*0.6f + 1000*0.4f*((float)(myUdpInBytes - myLastUdpInBytes))/time;
		
		myLastTcpOutBytes = myTcpOutBytes;
		myLastTcpInBytes = myTcpInBytes;
		myLastUdpOutBytes = myUdpOutBytes;
		myLastUdpInBytes = myUdpInBytes;
	}
	
	public long getMyTotalSpeedInBitsPerSecond()
	{
		return (long)  (myLastTcpOutRate+
		myLastTcpInRate+
		myLastUdpOutRate+
		myLastUdpInRate)/1024;
	}

}
