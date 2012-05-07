package edu.huji.cs.netutils.app;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.TCPPacketBuilder;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.parse.IPFactory;

/**
 * change tuple [source ip, source port, destination ip, destination port, type] 
 * 
 * 
 * @author roni bar yanai
 *
 */
public class CapChangeTuple
{

	
	
	public static void main(String[] args) throws NetUtilsException, IOException
	{
		CaptureFileReader rd = CaptureFileFactory.tryToCreateCaprtueFileReader("c:\\zatto.cap");
		
		CaptureIterator ir = new CaptureIterator(rd);
		
	    PCapFileWriter wr = new PCapFileWriter("c:\\roni.cap");
		
		while(ir.hasNext())
		{
			byte data[] = ir.next();
			
			if(IPFactory.isTCPPacket(data))
			{
				TCPPacketBuilder bld = new TCPPacketBuilder(IPFactory.createTCPPacket(data));
                wr.addPacket(bld.createTCPPacket().getRawBytes());			
			}
		}
		
		
	}
	
	
	
	
}
