package edu.huji.cs.netutils.examples;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.IPv4Packet;

/**
 * Example of counting the number of IPv4 packets.
 * 
 * @author roni bar-yanai
 *
 */
public class CountIPv4Packets
{

	public static void main(String[] args) throws IOException, NetUtilsException
	{
		if(args.length<1)
		{
			System.out.println("missing file name parameter");
			System.exit(-1);
		}
		
		CaptureIterator it = new CaptureIterator(CaptureFileFactory.createCaptureFileReader(args[0]));
        int n = 0;		
		int frag = 0;    
		// iterate over packets
		while( it.hasNext())
		{
			byte data[] = it.next();
			// is ipv4
			if (EthernetFrame.statIsIpv4Packet(data))
			{
				n++;
				// create matching object and use access
				// method to find is ip is fragmented.
				IPv4Packet ippacket = new IPv4Packet(data);
				if (ippacket.isFragmented())
				{
					frag++;
				}
			}
		}
		
		System.out.println("Total number of packet: "+n);
		
	}
}
