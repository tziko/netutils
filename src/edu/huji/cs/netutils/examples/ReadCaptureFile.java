package edu.huji.cs.netutils.examples;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureIterator;

/**
 * Example on how to read capture file using the {@link CaptureIterator}
 * 
 * @author roni bar-yanai
 *
 */
public class ReadCaptureFile
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
		        
		while( it.hasNext())
		{
			it.next();
			n++;
		}
		
		System.out.println("Total number of packet: "+n);
		
		/*while( it.hasNext())
		{
			byte data[] = it.next();
			if(EthernetFrame.statIsIpv4Packet(data) && IPv4Packet.getIpProtocolType(data) == IPPacketType.TCP)
			{
				TCPPacket tcp = new TCPPacket(data);
				System.out.println(tcp.toString());
			}
		}
*/		
	}
}
