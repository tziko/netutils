package edu.huji.cs.netutils.examples.ping;


import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.ICMPPacketBuilder;
import edu.huji.cs.netutils.build.IPv4PacketBuilder;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.inject.IPInjector;
import edu.huji.cs.netutils.parse.ICMPPacketType;
import edu.huji.cs.netutils.parse.IPv4Address;


/**
 * Example class that implements simple ping application.
 * 
 * @author roni bar-yanai
 *
 */
public class Ping
{

	private static final int DEFAILT_COUNT = 4;
	/**
	 * run the ping.
	 * 
	 * ping [args] destination ip.
	 * 
	 *  -c - number of times.
	 * 
	 *  
	 * @param args
	 * @throws NetUtilsException 
	 * @throws JInjectException
	 * @throws JPCAPException
	 */
	public static void main(String[] args) throws NetUtilsException
	{
		try
		{
		if(args.length>1)
		{
			System.out.println("Missing parameter: destination IP");
			System.exit(-1);
		}
		String targetIp = args[0];
				
		// number if icmp echo to send
		int count = DEFAILT_COUNT;
	
		if(args.length == 2)
		{
			count = Integer.parseInt(args[1]);
		}
		
		// initialize the jpcap on first interface found
		JPCap sniffer = new JPCap(JPCap.getAllIntefacesNames()[0].getName());

		// add ping listener
		sniffer.addListener(new PingListener(targetIp));

		// start sniffer
		sniffer.startJPcap();

		// init Ip injector on the same interface as the sniffer.
		IPInjector inj = new IPInjector(sniffer.getMyInterfaceName());

		// building the ip layer
		IPv4PacketBuilder ipv4 = new IPv4PacketBuilder();
		ipv4.setDstAddr(new IPv4Address(targetIp));
		ipv4.setSrcAddr(new IPv4Address(sniffer.getmyInterfaceIp()));
		
		// build the data. the data is any byte array.
		// in the implementation it contains pkt id,sequence and time stamp
		PingData pingdata = new PingData();
		pingdata.id = 1;
		pingdata.sequence = 200;
		pingdata.time = System.currentTimeMillis();

		// build the icmp packet
		ICMPPacketBuilder icmp = new ICMPPacketBuilder();
		// the type is echo request
		icmp.setType(ICMPPacketType.ECHO_REQUEST_TYPE);
		icmp.setCode(0);
		// set the data
		icmp.setPayload(pingdata.getAsByteArray());
		ipv4.addL4Buider(icmp);
		
		// inject according to the wanted count number
		for (int i = 0; i < count; i++)
		{
			inj.injcet( icmp.createICMPPacket().getIpv4Packet());
			sleep(1000);
			
			// change the sequence and the time stamp for next ping
			pingdata.sequence++;
			pingdata.time = System.currentTimeMillis();
			icmp.setPayload(pingdata.getAsByteArray());
		}

        // stop injector
		inj.releaseResource();

		// give the sniffer 5 more sec (for last replay to arrive )and close it.
		sleep(5000);
    	sniffer.stopJPcap();
		}
		catch (Throwable e)
		{
			e.printStackTrace();
		}
	}

	private static void sleep(long time)
	{
		try
		{
			Thread.sleep(time);
		}
		catch (InterruptedException e)
		{
		}
	}

}
