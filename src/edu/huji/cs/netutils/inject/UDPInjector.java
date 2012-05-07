package edu.huji.cs.netutils.inject;


import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.UDPPacketIpv4;
import edu.huji.cs.netutils.utils.IP;

/**
 * Class for injecting UDP packets.
 * (Using the interface macs)
 * 
 * @author roni bar-yanai
 *
 */
public class UDPInjector extends IPInjector
{

	private static final int CALCUALTE_UDP_CHECKSUM = 0;
	
	/**
	 * create new udp injector.
	 * 
	 * @param theInterfaceName - eth1,eth0 etc in linux and for example 
	 *     \\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC} in windows.
	 *     
	 * @throws NetUtilsException
	 */
	public UDPInjector(String theInterfaceName) throws NetUtilsException
	{
		super(theInterfaceName);
	}
	
	/**
	 * Inject udp packet.
	 * @param theTotalLength - total length without ip header.
	 * @param mySrcIp - as long
	 * @param myDstIp - as long
	 * @param mySrcPort - as int
	 * @param myDstPort - as int
	 * @param payload - byte array of the payload.
	 * @throws NetUtilsException
	 */
	public void injectUDP(int theTotalLength,long mySrcIp,long myDstIp,int mySrcPort,int myDstPort,byte payload[]) throws NetUtilsException
	{
		// make sure instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		if (payload == null)
			throw new NetUtilsException("Got null parameter");
		
		// call libnet c functions to configure.
		myJLibNetWraper.libnet_build_udp(mySrcPort,myDstPort ,theTotalLength, CALCUALTE_UDP_CHECKSUM,payload,myKey.getKeyAsInt());
		myJLibNetWraper.libnet_build_ipv4(theTotalLength+DEFAULT_HDR_LEN,DEFAULT_TOS,getSequenceID()
				,DEFAULT_FRAG,DEFAULT_TTL,IPPacketType.UDP,DEFAULT_DO_CHECK_SUM,(int)mySrcIp,(int)myDstIp
				,null,myKey.getKeyAsInt());
		
		// call c to inject packet.
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	/**
	 * Inject UDP packet.
	 * @param thePkt
	 * @throws NetUtilsException
	 */
	public void injcetUDP(UDPPacketIpv4 thePkt) throws NetUtilsException
	{
		// make sure instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		if (thePkt.isMandatoryFieldsSet() == false)
			throw new NetUtilsException("No all ip mandatory fileds were set");
		
		// auto complete checksum...etc.
		thePkt.atuoComplete();
		
		int frag = (thePkt.getFragmentFlags() << 13) & thePkt.getFragmentOffset(); 
		
		// call libnet c functions to configure packet.
		myJLibNetWraper.libnet_build_udp(thePkt.getSourcePort(),thePkt.getDestinationPort() ,thePkt.getUDPLength(), thePkt.getUDPChecksum(),thePkt.getUDPData(),myKey.getKeyAsInt());
		myJLibNetWraper.libnet_build_ipv4(thePkt.getUDPLength()+DEFAULT_HDR_LEN,DEFAULT_TOS,thePkt.getId()
				,frag,thePkt.getTTL(),IPPacketType.UDP,thePkt.getIPChecksum(),(int)((IPv4Address)thePkt.getUnderlyingIPPacketBase().getSourceIP()).getIPasLong()
				,(int)((IPv4Address)thePkt.getUnderlyingIPPacketBase().getDestinationIP()).getIPasLong()
				,null,myKey.getKeyAsInt());
		
		
		// inject packet.
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	
	public static void main(String[] args) throws NetUtilsException
	{
       UDPInjector inj = new UDPInjector("\\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC}");
		
		byte[] data = new byte[1000];
		
		for (int i = 0; i < data.length; i++)
		{
			data[i] = (byte) i;
		}
		
		UDPPacketIpv4 pkt = new UDPPacketIpv4();
		pkt.setSrcIp(IP.getIPAsLong("64.103.125.81"));
		pkt.setDstIp(IP.getIPAsLong("64.103.125.161"));
		pkt.setData(data);
		pkt.setSrcPort(4000);
		pkt.setDstPort(4001);
		 
		long time = System.currentTimeMillis();
		
		for(int i=0 ; i<1000 ; i++)
			inj.injcetUDP(pkt);
			//inj.injectUDP(8+data.length,IP.getIPAsLong("64.103.125.81"),IP.getIPAsLong("64.103.125.161"),5000,9000,data);
		//inj.inject(200,(int) IP.getIPAsLong("64.103.125.81"),(int) IP.getIPAsLong("64.103.125.161"),data);
		
		System.out.println("time passed : "+(System.currentTimeMillis() - time));
		
		inj.releaseResource();
	}

}
