package edu.huji.cs.netutils.examples;

import java.io.IOException;
import java.util.HashSet;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.IPFactory;

/**
 * Example of counting flows in capture file.
 * 
 * @author roni bar-yanai
 *
 */
public class CountFlows
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
			
			// check if ipv4
			if (EthernetFrame.statIsIpv4Packet(data))
			{
				// check if TCP or UDP and five tuple
				// so we don't count two packets of the
				// same flows
				if (IPFactory.isTCPPacket(data))
				{
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
