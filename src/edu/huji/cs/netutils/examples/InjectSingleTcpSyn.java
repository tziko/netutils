package edu.huji.cs.netutils.examples;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.IPv4PacketBuilder;
import edu.huji.cs.netutils.build.TCPPacketBuilder;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.inject.TCPInjector;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
/**
 * Injecting a single TCP SYN packet through the
 *  default interface.
 * 
 * @author roni bar-yanai
 *
 */
public class InjectSingleTcpSyn
{
	public static void main(String[] args) throws InterruptedException
	{
		try
		{
			// init injector using first interface name
			TCPInjector inj = new TCPInjector(JPCap.getAllIntefacesNames()[0].getName());
			
			// build TCP part
			TCPPacketBuilder tcppkt = new TCPPacketBuilder();
			tcppkt.setSrcPort(4000);
			tcppkt.setDstPort(4001);
			tcppkt.setSYNFlag(true);
			tcppkt.setSeqNum(0);
			
			// IP part
			IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
			ipv4.setSrcAddr(new IPv4Address(inj.getIp()));
			ipv4.setDstAddr(new IPv4Address("64.103.125.91"));
			
			// connet IP and TCP (Ethetnet is auot completed)
			ipv4.addL4Buider(tcppkt);
			
			inj.injectTCP((TCPPacketIpv4) tcppkt.createTCPPacket());
			
			inj.releaseResource();
		}
		catch (NetUtilsException e)
		{
			e.printStackTrace();
		}
	}
}
