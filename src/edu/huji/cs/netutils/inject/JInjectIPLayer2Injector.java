package edu.huji.cs.netutils.inject;

import java.util.Random;


import edu.huji.cs.netutils.NetUtilsException;

import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.inject.impl.JInjectKey;
import edu.huji.cs.netutils.inject.impl.JLibNetWraper;
import edu.huji.cs.netutils.parse.EthernetFrameType;
import edu.huji.cs.netutils.parse.IPv4Packet;

/**
 * Class for injecting raw IP packets.
 * The user must also set the mac addresses.
 * 
 * @author roni bar-yanai
 *
 */
public class JInjectIPLayer2Injector
{

	/**
	 * the used defaults on auto complete.
	 */
	public static final int DEFAULT_TTL = 64;
	public static final int DEFAULT_HDR_LEN = 20;
	public static final int DEFAULT_TOS = 0;
	public static final int DEFAULT_FRAG = 0;
	public static final int DEFAULT_DO_CHECK_SUM = 0;
	
	private  static final int INT16_MAX = 65536;
	
	/**
	 * the instance key
	 */
	protected JInjectKey myKey = null;
	
	/*
	 * 
	 */
	protected JLibNetWraper myJLibNetWraper = null;
	
	protected boolean _isBinded = false;
	
	/**
	 * used to create random sequnace num
	 */
	private Random myRand = null;
		
	/**
	 * create new injector 
	 * @param theInterfaceName - the interface name ( "eth1","eth0"...etc in linux).
	 * @throws NetUtilsException
	 */
	public JInjectIPLayer2Injector(String theInterfaceName) throws NetUtilsException
	{
		myJLibNetWraper = JLibNetWraper.getInsance(); 
		myKey = myJLibNetWraper.libnetInitLinkLayer(theInterfaceName);
		_isBinded = true;
	}
	
	/**
	 * create new injcetor.
	 * will use the first interface found.
	 * @throws NetUtilsException
	 * @throws JPCAPException 
	 */
	public JInjectIPLayer2Injector() throws NetUtilsException
	{
		this(JPCap.getInterfaceName());
		
	}
	
	/**
	 * Inject the IP packet. The packet should be configured with
	 * layer 2 details (mac addresses, packet type...etc)
	 * @param thePkt
	 * @throws NetUtilsException
	 */
	public void injcet(IPv4Packet thePkt) throws NetUtilsException
	{
		// check if was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
				
		// check that user configured the mandatory fields.
		if (thePkt.isMandatoryFieldsSet() == false)
			throw new NetUtilsException("No all ip mandatory fileds were set");
		
		if (thePkt.getSrcMacByteArray() == null || thePkt.getDstMacByteArray() == null)
			throw new NetUtilsException("No mac addresses were set");
		
		// complete checksums and other params the were left
		// empty by the user.
		thePkt.atuoComplete();
		
		int frag = (thePkt.getFragmentFlags() << 13) & thePkt.getFragmentOffset();
		
		// configure libnet c ip4 layer 
		myJLibNetWraper.libnet_build_ipv4(thePkt.getIpPktTotalLength(),thePkt.getTypeOfService()
				,thePkt.getId(),frag,thePkt.getTTL(),thePkt.getIPProtocol(),thePkt.getIPChecksum()
				,(int)thePkt.getSourceIPv4().getIPasLong(),(int)thePkt.getDestinationIPv4().getIPasLong(),thePkt.getIPData(),myKey.getKeyAsInt());
		
		// configure c libnet.
		myJLibNetWraper.libnet_build_ethernet(thePkt.getDstMacByteArray(),thePkt.getSrcMacByteArray(),EthernetFrameType.IP_CODE,null,myKey.getKeyAsInt());
		
		// call c libnet inject
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	
	
	/**
	 * will close all resources used by the libnet instance.
	 */
	public void releaseResource()
	{
		if (_isBinded == true)
		{
			myJLibNetWraper.libnet_destroy(myKey.getKeyAsInt());
			_isBinded = false;
		}
	}
	
	protected void finalize() throws Throwable
	{
		releaseResource();
	}
	
	/**
	 * @return rand int
	 */
	protected int getRandInt()
	{
		if (myRand == null)
		{
			myRand = new Random(System.currentTimeMillis());
		}
		
		return myRand.nextInt(INT16_MAX);
	}
	
	private short _lastid = 0;
	
	boolean _isSquenceInitialized = false;
	
	/**
	 * @return
	 */
	protected int getSequenceID()
	{
		if (_isSquenceInitialized == false)
		{
			_isSquenceInitialized = true;
			_lastid = (short) getRandInt();
		}
		return _lastid++;
	}
}
