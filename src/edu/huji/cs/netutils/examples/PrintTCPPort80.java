package edu.huji.cs.netutils.examples;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.capture.JPCapTCPPktListener;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;

/**
 * Example of sniffing TCP packets on port 80 and printing
 * their content to the standard output.
 * 
 * @author roni bar-yanai
 *
 */
public class PrintTCPPort80
{
	public static void main(String[] args) throws NetUtilsException, IOException
	{
		String filter = "tcp port 80";
		String subnet = "255.255.255.0";
		
		// bind to first interface found
		JPCap jpcap = new JPCap();
		jpcap.setFilter(filter, subnet);
		
		// add tcp listener that only prints the packet content as Hex. 
		jpcap.addListener(new JPCapTCPPktListener()
		{
			public void processPacket(TCPPacketIpv4 thePkt)
			{
				
				System.out.println(thePkt.toHex());
			}
		});
		
		jpcap.startJPcap();
		System.in.read();
		jpcap.stopJPcap();
	}

}
