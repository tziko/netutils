package edu.huji.cs.netutils.inject;


import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.MACAddress;
import edu.huji.cs.netutils.parse.EthernetFrameType;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.UDPPacketIpv4;
import edu.huji.cs.netutils.utils.IP;

/**
 * Class for injecting UDP packets. 
 * User has control on mac addresses as well. 
 * 
 * @author roni bar-yanai
 */
public class JInjectUDPLayer2Injector extends JInjectIPLayer2Injector
{
	
	/**
	 * create new udp injector
	 * @param theInterfaceName - the interface name
	 * @throws NetUtilsException
	 */
	public JInjectUDPLayer2Injector(String theInterfaceName) throws NetUtilsException
	{
		super(theInterfaceName);
	}
	
	/**
	 * create new instance.
	 * will bind to the first interface found.
	 * @throws NetUtilsException
	 * @throws JPCAPException 
	 */
	public JInjectUDPLayer2Injector() throws NetUtilsException
	{
		super();
	}
		
	/**
	 * inject the udp packet.
	 * the packet mac addresses must be set.
	 * 
	 * @param thePkt
	 * @throws NetUtilsException
	 */
	public void injcetUDP(UDPPacketIpv4 thePkt) throws NetUtilsException
	{
		// make sure instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		// check that use has set the mandatoy fields
		if (thePkt.isMandatoryFieldsSet() == false)
			throw new NetUtilsException("No all ip mandatory fileds were set");
		
		if (thePkt.getUnderlyingIPPacketBase().getSrcMacByteArray() == null || thePkt.getUnderlyingIPPacketBase().getDstMacByteArray() == null)
			throw new NetUtilsException("No mac addresses were set");
		
		// auto complete checksum ...etc.
		thePkt.atuoComplete();
		
		int frag = (thePkt.getFragmentFlags() << 13) & thePkt.getFragmentOffset(); 
		
		// call libnet c functions to configure.
		myJLibNetWraper.libnet_build_udp(thePkt.getSourcePort(),thePkt.getDestinationPort() ,thePkt.getUDPLength(), thePkt.getUDPChecksum(),thePkt.getUDPData(),myKey.getKeyAsInt());
		myJLibNetWraper.libnet_build_ipv4(thePkt.getUDPLength()+DEFAULT_HDR_LEN,DEFAULT_TOS,thePkt.getId()
				,frag,thePkt.getTTL(),IPPacketType.UDP,thePkt.getIPChecksum(),(int)((IPv4Address)thePkt.getUnderlyingIPPacketBase().getSourceIP()).getIPasLong()
				,(int)((IPv4Address)thePkt.getUnderlyingIPPacketBase().getDestinationIP()).getIPasLong()
				,null,myKey.getKeyAsInt());
		
		myJLibNetWraper.libnet_build_ethernet(thePkt.getDstMacByteArray(),thePkt.getSrcMacByteArray(),EthernetFrameType.IP_CODE,null,myKey.getKeyAsInt());
		
		// inject packet.
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	
	public static void main(String[] args) throws NetUtilsException
	{
        JInjectUDPLayer2Injector inj = new JInjectUDPLayer2Injector("\\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC}");
		
		byte[] data = new byte[1000];
		
		for (int i = 0; i < data.length; i++)
		{
			data[i] = (byte) i;
		}
		
		UDPPacketIpv4 pkt = new UDPPacketIpv4();
		pkt.setSrcIp(IP.getIPAsLong("64.103.125.81"));
		pkt.setDstIp(IP.getIPAsLong("255.0.0.0"));
		pkt.setData(data);
		pkt.setSrcPort(4000);
		pkt.setDstPort(4001);
		
		pkt.setDstMacAddress(new MACAddress("FF:FF:FF:FF:FF:FF").asByteArray());
		pkt.setSrcMacAddress(new MACAddress("00:DE:AD:DE:AD:00").asByteArray()); 
		
		long time = System.currentTimeMillis();
		
		for(int i=0 ; i<20 ; i++)
			inj.injcetUDP(pkt);
		
		System.out.println("time passed : "+(System.currentTimeMillis() - time));
		
		inj.releaseResource();
	}
}
