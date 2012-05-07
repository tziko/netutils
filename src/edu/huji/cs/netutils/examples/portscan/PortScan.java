package edu.huji.cs.netutils.examples.portscan;

import edu.huji.cs.netutils.build.IPv4PacketBuilder;
import edu.huji.cs.netutils.build.TCPPacketBuilder;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.capture.JPCapTCPPktListener;
import edu.huji.cs.netutils.inject.TCPInjector;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
import edu.huji.cs.netutils.utils.ArgsParser;
import edu.huji.cs.netutils.utils.IP;


/**
 * 
 * The program implements simple port scanner.<br>
 * It searches for open ports on a remote host (or local).<br>
 * 
 * @author roni bar-yanai
 *
 */
public class PortScan
{
	private static final int MAX_PORT = 65536;
	
	/**
	 * 
	 * @param args
	 * @return
	 */
	public static ArgsParser initLineArgs(String [] args)
	{
		ArgsParser larg = new ArgsParser();
		larg.addArg("-d",1,"the destination ip");
		larg.addArg("-s",1,"the source ip");
		larg.init(args);
		
		return larg;
	}
	
	/**
	 * Algorythm:
	 * 
	 *   1. open JPcap on the first interface found.
	 *   2. open tcp listener
	 *   3. open tcp injector 
	 *   4. injects syn packets on all port on the dset ip
	 * 
	 * @param args
	 */
	public static void main(String[] args)
	{
		// init parameters
		ArgsParser larg = initLineArgs(args);
		String dstip = null;
		String srcip = null;
		String mask = "255.255.255.0";
		if (larg.hasOption("-d") && larg.hasOption("-s"))
		{
			dstip = larg.getArgAsString("-d");
			srcip = larg.getArgAsString("-s");
			if (IP.isValidIp(dstip) == false || IP.isValidIp(srcip) == false)
			{
				System.out.println("Got illegal destination ip : "+dstip+", "+srcip);
				System.exit(-1);
			}
		}
		else
		{
			System.out.println("Missing parameters: -s [src ip] -d [dst ip]");
			System.exit(-1);
		}
		
		
		try
		{
			// open sniffer on the first interface found
			JPCap sniffer = new JPCap();
			
			// set filter on the dst ip
			sniffer.setFilter("host "+dstip,IP.getIPAsLong(mask));
			
			// create tcp listener
			sniffer.addListener(new JPCapTCPPktListener(){

				/**
				 * 
				 */				
				public void processPacket(TCPPacketIpv4 thePkt)
				{
					// if the packet ack falg is on
					if (thePkt.isAck())
					{
						// if the packet syn ack is on
						if (thePkt.isSyn())
						{
							System.out.println("Source IP: "+thePkt.getUnderlyingIPPacketBase().getSourceIPAsString());
						    System.out.println("Got syn,ack on port "+thePkt.getSourcePort()+", "+thePkt.getDestinationPort());
						}
					}
				}});

			// start the sniffer
			sniffer.startJPcap();
			
			// init the injector on the same interface as the sniffer
			TCPInjector inj = new TCPInjector(sniffer.getMyInterfaceName());
			
			// build the tcp packet
			IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
			ipv4.setDstAddr(new IPv4Address(dstip));
			ipv4.setSrcAddr(new IPv4Address(srcip));
			
			TCPPacketBuilder tcp = new TCPPacketBuilder();
			tcp.setSrcPort(4000);
			tcp.setSYNFlag(true);
			tcp.setSeqNum(0);
			
			ipv4.addL4Buider(tcp);
						
			// run on all port wanted range 
			for(int i=0,port=1 ; i<MAX_PORT ; i++,port++)
			{
				tcp.setDstPort(port);
				//pkt.setDestinationPort(port);
    		    inj.injectTCP((TCPPacketIpv4) tcp.createTCPPacket());
    		   
    		    // every 100 syn sleep for a while 
    		    // make sure not overloading the target pc
    		    if (i%100==0 && i>0)
    		    {
    		    	Thread.sleep(100);
    		    }
			}
			
			// clean the injector and the sniffer
			inj.releaseResource();
			sniffer.stopJPcap();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}
}
