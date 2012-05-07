package edu.huji.cs.netutils.inject;


import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.capture.JPCapTCPPktListener;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
import edu.huji.cs.netutils.utils.IP;


/**
 * Class for injecting TCP packets.
 * 
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class TCPInjector extends IPInjector
{

	/**
	 * create new tcp injector.
	 * 
	 * @param theInterfaceName - eth1,eth0 etc in linux and for example 
	 *     \\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC} in windows.
	 *     
	 * @throws NetUtilsException
	 */
	public TCPInjector(String theInterfaceName) throws NetUtilsException
	{
		super(theInterfaceName);
    }
	
	/**
	 * create new tcp injector. bind injector to first interface.
	 * 
	 * @throws NetUtilsException
	 */
	public TCPInjector() throws NetUtilsException
	{
		super();
    }

	/**
	 * inject the packet with the following parameters.
	 * @param sip - sourc ip as int
	 * @param sp - source port
	 * @param dip - destination ip as int
	 * @param dp - destination port
	 * @param seq - tcp sequance num
	 * @param ack - tcp ack num
	 * @param flags - the tcp flags as int (only last 6 bits matter)
	 * @param winSize - tcp window size
	 * @param chksum - the check sum, put 0 for automatically
	 * @param urgPtr - tcp urgent pointer val
	 * @param totalTcpPktLn - the total tcp packet len (without the ip header)
	 * @param payload - the payload as byte array.
	 * @throws NetUtilsException
	 */
	public void injectTCP(long sip,long sp,long dip,long dp,long seq,long ack,short flags,long winSize,long chksum,long urgPtr,long totalTcpPktLn,byte[] payload) throws NetUtilsException
	{
		// make sure instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		if (payload == null)
			throw new NetUtilsException("Got null parameter");
		
		// call libnet c functions for configuring the packet.
		myJLibNetWraper.libnet_build_tcp(sp,dp,seq,ack,flags,winSize,chksum,urgPtr,totalTcpPktLn,payload,myKey.getKeyAsInt());
		myJLibNetWraper.libnet_build_ipv4((int) (totalTcpPktLn+DEFAULT_HDR_LEN),DEFAULT_TOS,getSequenceID()
				,DEFAULT_FRAG,DEFAULT_TTL,IPPacketType.UDP,DEFAULT_DO_CHECK_SUM,(int)sip,(int)dip
				,null,myKey.getKeyAsInt());
		
		// inject packet.
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	/**
	 * Inject tcp packet 
	 * @param thePkt - the tcp packet obj.
	 * @throws NetUtilsException
	 */
	public void injectTCP(TCPPacketIpv4 thePkt) throws NetUtilsException
	{
		// make sure instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		// check all most parameters were filled (such as src port and ip)
		if (thePkt.isMandatoryFieldsSet() == false)
			throw new NetUtilsException("No all ip mandatory fileds were set");
		
		// complete all unfilled fields 
		thePkt.atuoComplete();
		
		// first build the tcp part
		myJLibNetWraper.libnet_build_tcp(thePkt.getSourcePort(),thePkt.getDestinationPort()
				,thePkt.getSequenceNumber(),thePkt.getAcknowledgmentNumber(),
				(short)thePkt.getAllFlags(),thePkt.getWindowSize(),thePkt.getTCPChecksum(),
				thePkt.getUrgentPointer(),thePkt.getTotalTCPPlength(),thePkt.getTCPData(),myKey.getKeyAsInt());
		
		// build the ip part
		myJLibNetWraper.libnet_build_ipv4(thePkt.getTotalTCPPlength()+DEFAULT_HDR_LEN,DEFAULT_TOS,getSequenceID()
				,DEFAULT_FRAG,DEFAULT_TTL,IPPacketType.TCP,DEFAULT_DO_CHECK_SUM,(int)((IPv4Address)thePkt.getUnderlyingIPPacketBase().getSourceIP()).getIPasLong(),(int)((IPv4Address)thePkt.getUnderlyingIPPacketBase().getDestinationIP()).getIPasLong()
				,null,myKey.getKeyAsInt());
		
		// inject packet.
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	public static void main(String[] args)
	{
		try
		{
			JPCap sniffer = new JPCap("\\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC}");
			
			sniffer.setFilter("host 64.103.125.161",IP.getIPAsLong("255.255.255.0"));
			
			sniffer.addListener(new JPCapTCPPktListener(){

				public void processPacket(TCPPacketIpv4 thePkt)
				{
					if (thePkt.isAck())
					{
						if (thePkt.isSyn())
						{
							System.out.println("src ip: "+thePkt.getUnderlyingIPPacketBase().getSourceIPAsString());
						    System.out.println("Got syn,ack on port "+thePkt.getSourcePort()+", "+thePkt.getDestinationPort());
						    System.out.println("flag = "+thePkt.getAllFlags());
						}
					}
				}});
			
			sniffer.startJPcap();
			
			TCPInjector inj = new TCPInjector("\\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC}");
			TCPPacketIpv4 pkt = new TCPPacketIpv4();
			pkt.setSrcIp(IP.getIPAsLong("64.103.125.81"));
			pkt.setDstIp(IP.getIPAsLong("64.103.125.161"));
			pkt.setSourcePort(4000);
			pkt.setSyn(true);
			pkt.setSequenceNum(0);
		
			for(int i=0,port=1 ; i<4000 ; i++,port++)
			{
				pkt.setDestinationPort(port);
    		    inj.injectTCP(pkt);
			}
			
			inj.releaseResource();
			sniffer.stopJPcap();
		}
		catch (NetUtilsException e)
		{
			e.printStackTrace();
		}
	}
	
}
