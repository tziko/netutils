package edu.huji.cs.netutils.inject;

import java.util.Random;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.inject.impl.JInjectKey;
import edu.huji.cs.netutils.inject.impl.JLibNetWraper;
import edu.huji.cs.netutils.parse.IPv4Packet;

/**
 * Class for injecting for ip level packets.<br>
 * (Will use the interface mac addresses)<br>
 * @author roni bar-yanai
 */
public class IPInjector
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
	
	// holds reference to the bounded interface.
	private String myIp = null;
		
	/**
	 * create new instance 
	 * @param theInterfaceName - the interface name ( "eth1","eth0"...etc in linux).
	 * @throws NetUtilsException
	 */
	public IPInjector(String theInterfaceName) throws NetUtilsException
	{
		myJLibNetWraper = JLibNetWraper.getInsance();
		myIp = JPCap.getIpForInterface(theInterfaceName);
		myKey = myJLibNetWraper.libnetInitRawIp(theInterfaceName);
		_isBinded = true;
	}
	
	/**
	 * create new instance.
	 * will use the first interface found.
	 * @throws NetUtilsException
	 * @throws JPCAPException 
	 */
	public IPInjector() throws NetUtilsException
	{
		this(JPCap.getInterfaceName());
	}
	
	/**
	 * Inject IP packet
	 * @param thePkt
	 * @throws NetUtilsException
	 */
	public void injcet(IPv4Packet thePkt) throws NetUtilsException
	{
		// check that instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		/// make sure user has set the mandatory fields
		if (thePkt.isMandatoryFieldsSet() == false)
			throw new NetUtilsException("No all ip mandatory fileds were set");
		
		// complete checksums...etc
		thePkt.atuoComplete();
		
		int frag = (thePkt.getFragmentFlags() << 13) & thePkt.getFragmentOffset(); 
		
		// call c ipv4 configuration
		myJLibNetWraper.libnet_build_ipv4(thePkt.getIpPktTotalLength(),thePkt.getTypeOfService()
				,thePkt.getId(),frag,thePkt.getTTL(),thePkt.getIPProtocol(),thePkt.getIPChecksum()
				,(int)thePkt.getSourceIPv4().getIPasLong(),(int)thePkt.getDestinationIPv4().getIPasLong(),thePkt.getIPData(),myKey.getKeyAsInt());
		
		// inject packet
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	/**
	 * Inject ip pakcet
	 * @param len - the total length of the packet
	 * @param tos - type of service
	 * @param id - the packet id num (16 unsinged int)
	 * @param frag - the frgmantion (16 bit - 3 bit flags and 13 offset)
	 * @param ttl  - the ttl val
	 * @param prot - the protocol ( 0x06 fot tcp ...etc)
	 * @param sum - the chksum ( DEFAULT_DO_CHECK_SUM for auto completion)
	 * @param src - src ip as int
	 * @param dst - dst ip as int
	 * @param payload - the payload bytes
	 * @throws NetUtilsException
	 */
	public void inject(int len, int tos, int id, int frag,int ttl, int prot, int sum, int src, int dst,
			 byte[] payload) throws NetUtilsException
	{
		// make sure instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		if (payload == null)
			throw new NetUtilsException("Got null parameter");
		
		myJLibNetWraper.libnet_build_ipv4(len,tos,id,frag,ttl,prot,sum,src,dst,payload,myKey.getKeyAsInt());
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	/**
	 * inject ip packet where all missing parameters will be auto completed.
	 * @param proto - protocol type
	 * @param src - the src ip as int
	 * @param dst - dst ip as int
	 * @param payload - the payload byte array
	 * @throws NetUtilsException
	 */
	public void inject(int proto,int src,int dst,byte[] payload) throws NetUtilsException
	{
		// make sure instance was initialized successfully
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't initialized properly");
		
		// 
		if (payload == null)
			throw new NetUtilsException("Got null parameter");
		
		inject(DEFAULT_HDR_LEN+payload.length,DEFAULT_TOS,getRandInt(),DEFAULT_FRAG,DEFAULT_TTL,proto,DEFAULT_DO_CHECK_SUM,src,dst,payload);
	}
	
	/**
	 * will close all libnet resources used by the instance.
	 */
	public void releaseResource()
	{
		if (_isBinded == true)
		{
			myJLibNetWraper.libnet_destroy(myKey.getKeyAsInt());
			_isBinded = false;
		}
	}
	
	/**
	 * (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	protected void finalize() throws Throwable
	{
		// to be on the safe side.
		releaseResource();
	}
	
	/**
	 * used for sequencing auto completion
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
	 * @return sequance id
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
	
	/**
	 * 
	 * @return the interface IP
	 */
	public String getIp()
	{
		return myIp;
	}
}
