package edu.huji.cs.netutils.examples;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.IPFactory;
import edu.huji.cs.netutils.parse.TCPPacket;

/**
 * Example of counting number of TCP segments which has SYN
 *  or RST flags on
 *  
 * @author roni bar-yanai
 *
 */
public class CountTCPSynAndRst
{
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		if(args.length<1)
		{
			System.out.println("missing file name parameter");
			System.exit(-1);
		}
		
		CaptureIterator it = new CaptureIterator(CaptureFileFactory.createCaptureFileReader(args[0]));
        int syn = 0;		
		int rst = 0;     
		
		// iteratre over all packets
		while( it.hasNext())
		{
			byte data[] = it.next();
			
			// is ipv4?
			if (EthernetFrame.statIsIpv4Packet(data))
			{
				// is TCP?
				if (IPFactory.isTCPPacket(data))
				{
					// create TCP object and check if flags
					// are up.
					TCPPacket tcppkt = new TCPPacket(data);
					if(tcppkt.isSyn())
					{
						syn++;
					}
					if(tcppkt.isRst())
					{
						rst++;
					}
				}
			}
		}
		
		System.out.println("Total Syn:"+syn);
		System.out.println("Total Rst:"+rst);
		
	}

}
