package edu.huji.cs.netutils.examples;

import java.io.IOException;
import java.util.HashSet;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.IPFactory;
import edu.huji.cs.netutils.parse.IPv4Packet;
import edu.huji.cs.netutils.parse.TCPPacket;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
import edu.huji.cs.netutils.parse.TCPPacketIpv6;

public class CountFlowsIPv6Compliant
{
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		if(args.length<1)
		{
			System.out.println("missing file name parameter");
			System.exit(-1);
		}
		
		CaptureIterator it = new CaptureIterator(CaptureFileFactory.createCaptureFileReader(args[0]));
        HashSet<FiveTuple> udps = new HashSet<FiveTuple>();	
        HashSet<FiveTuple> tcps = new HashSet<FiveTuple>();
        
		while( it.hasNext())
		{
			byte data[] = it.next();
			if (IPFactory.isIPPacket(data))
			{
				if (IPFactory.isTCPPacket(data))
				{
					if(IPv4Packet.statIsIpv4Packet(data))
					{
						TCPPacketIpv4 tcppkt = new TCPPacketIpv4(data);
					}
					else
					{
						TCPPacketIpv6 tcppkt = new TCPPacketIpv6(data);
					}
					TCPPacket tcppkt = IPFactory.createTCPPacket(data);
					
					tcps.add(new FiveTuple(data));
				}
				else if (IPFactory.isUDPPacket(data))
				{
					udps.add(new FiveTuple(data));
				}
				
			}
		}
		
		System.out.println("Total TCP Flows:"+tcps.size());
		System.out.println("Total UDP Flows:"+udps.size());
		
	}
}
