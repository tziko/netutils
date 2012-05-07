package edu.huji.cs.netutils.examples;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.capture.JPCapTCPPktListener;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;

/**
 * The class shows example of recording TCP traffic on port 80
 * into PCap formated file.
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class RecordTCPPort80
{
	public static void main(String[] args) throws NetUtilsException, IOException
	{
		if(args.length<1)
		{
			System.out.println("missing file name parameter");
			System.exit(-1);
		}
		
		final PCapFileWriter fwr = new PCapFileWriter(args[0]);
				
		// bind to first interface found
		JPCap jpcap = new JPCap();
				
		// add tcp listener that only prints the packet content as Hex. 
		jpcap.addListener(new JPCapTCPPktListener()
		{
			public void processPacket(TCPPacketIpv4 thePkt)
			{
				if(thePkt.getDestinationPort() == 80 || thePkt.getDestinationPort() == 80)
				{
					try {
						fwr.addPacket(thePkt.getRawBytes());
					} catch (IOException e) {
						e.printStackTrace();
					} catch (NetUtilsException e) {
						e.printStackTrace();
					}
				}
			}
		});
		
		jpcap.startJPcap();
		System.in.read();
		fwr.close();
		jpcap.stopJPcap();
	}
}
