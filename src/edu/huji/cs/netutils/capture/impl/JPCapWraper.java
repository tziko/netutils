package edu.huji.cs.netutils.capture.impl;

import java.util.HashMap;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.inject.IPInjector;



/**
 * Wrap the pcap c lib.
 * Used by JPCap class.
 * 
 * require netutils.so or neturils.dll to be in the jre java.library.path
 * This class should not be used directly by users.
 * Use the JPCap.
 * 
 * @author roni bar-yanai
 *
 */
public class JPCapWraper
{
	// buffer size for packets.	
	private static final int DEFAULT_BUFF_SIZE = 65535;

	private static final int DEFAULT_WAIT_TIME = 500;

	/*
	 * each jwrapper instance is represented by key (supplied by opne_live...)
	 * this constant stands for no more instance can be created.
	 */
	private static final int NO_KEY_RETURNED = -1;

	/*
	 * singleton instance
	 */
	private static JPCapWraper INSTANCE = null;

	// will hold all currently open instances of jpcap for process packet
	private HashMap<Integer,JPCap> myOpenJpcapInst = new HashMap<Integer,JPCap>();

	/**
	 * @return JPcapWraper instance.
	 * @throws NetUtilsException 
     */
	public static synchronized JPCapWraper getJPCapWriter() throws NetUtilsException
	{
		// initialize component.
		try
		{
			if (INSTANCE == null)
			{
				// load dll, will cause exception in case dll is not
				// founded on the jave.libray.path
				System.loadLibrary("netutils");
				INSTANCE = new JPCapWraper();
			}
		}
		catch (UnsatisfiedLinkError e)
		{
			throw new NetUtilsException(e);
		}
		return INSTANCE;
	}

	/*
	 * singleton
	 */
	private JPCapWraper()
	{
	}

	/**
	 * open new instance of pcap 
	 * @param theInterfaceName - the eth card name (eth1,eth0 in linux)
	 * @param theBufferSize - the wanted buffer size. usually 65535 will be enoguh
	 * @param isPromisc - if true will listen to all packets
	 * @param waitMsec - wait time between dispatching packets
	 * @return JPCapKey - return a key that uniquely identifies the instance. 
	 * @throws NetUtilsException if didn't success
	 */
	public synchronized JPCapKey pcap_open_live(String theInterfaceName, int theBufferSize, boolean isPromisc, int waitMsec) throws NetUtilsException
	{
		// try to open instance of pcap
		int key = pcap_open_live(theInterfaceName, theBufferSize, (isPromisc ? 1 : 0), waitMsec);

		if (key == NO_KEY_RETURNED)
		{
			throw new NetUtilsException(getLastError(key));
		}
		else
			return new JPCapKey(key);

	}

	/**
	 * open new instacne of pcap
	 * @param theInterface - the wanted interface (on linux eth1,eth0...etc)
	 * @return the JPcapKey for the instance
	 * @throws NetUtilsException - if din't succedd.
	 */
	public JPCapKey pcap_open_live(String theInterface) throws NetUtilsException
	{
		return pcap_open_live(theInterface, DEFAULT_BUFF_SIZE, true, DEFAULT_WAIT_TIME);
	}

	/**
	 * wait until number of packets have been received.
	 * will call processPacket on each packet received.
	 * @param thePcap - the JPcap instance
	 * @param theNumOfPkt - the number of packets to wait.
	 * @throws NetUtilsException
	 */
	public void pcap_dispatch(JPCap thePcap, int theNumOfPkt) throws NetUtilsException
	{
		JPCapKey key = thePcap.getMyJPCapKey();

		if (key == null)
		{
			throw new NetUtilsException("Didn't initialized pcap properly");
		}

		// keep it for matching.
		myOpenJpcapInst.put(new Integer(key.getKeyAsInt()), thePcap);

		// call the native method
		pcap_dispatch(key.getKeyAsInt(), theNumOfPkt);
	}

	/**
	 * get the next packet sniffed.
	 * @param thePcap
	 * @return the packet
	 * @throws NetUtilsException
	 */
	public byte[] pcap_next(JPCap thePcap) throws NetUtilsException
	{
		JPCapKey key = thePcap.getMyJPCapKey();

		if (key == null)
		{
			throw new NetUtilsException("Didn't initialized pcap properly");
		}

		// call the native method.
		return pcap_next(key.getKeyAsInt());
	}

	/**
	 * Set filter on JPcap instance.
	 * @param theJPcap 
	 * @param theFilter - string represent the filter (like tcpdump) 
	 * @param netmask - the netmask as long
	 * @return true set filter success and false otherwise.
	 * @throws NetUtilsException
	 */
	public boolean setFilter(JPCap theJPcap, String theFilter, long netmask) throws NetUtilsException
	{
		JPCapKey key = theJPcap.getMyJPCapKey();

		if (key == null)
		{
			throw new NetUtilsException("Didn't initialized pcap properly");
		}

		// call native method
		int result = pcap_set_filter(key.getKeyAsInt(), theFilter, netmask);

		return (result > 0);
	}

	/**
	 * Close pcap instance
	 * @param theJPcap
	 */
	public void close(JPCap theJPcap)
	{
		JPCapKey key = theJPcap.getMyJPCapKey();

		if (key == null)
		{
			return;
		}
		else
		{
			pcap_close(key.getKeyAsInt());
		}
	}

	/**
	 * called by the c code when packet arrives.
	 * @param thePacket - the packet byte array.
	 * @param key - the matching jpcap instance key
	 */
	public void processPacket(byte[] thePacket, int key)
	{
		if (myOpenJpcapInst.containsKey(new Integer(key)))
		{
			JPCap tmp = (JPCap) myOpenJpcapInst.get(new Integer(key));
			tmp.packetArrived(thePacket);
		}
	}

	/**
	 * will return all devices on pc (that are network and have ip configured).
	 * @return array of devices name and address/
	 * [0] name1
	 * [1] ip of name1
	 * [2] name 2
	 * [3] ip of name2
	 * .
	 * .
	 * . 
	 */
	public String[] getAllNetDevicesNames()
	{
		String toRetrun = get_all_devices(true);
		return toRetrun.split("\n");
	}

	/**
	 * native method for open pcap instance
	 * @param theInter
	 * @param buffsize
	 * @param promisc
	 * @param msec
	 * @return key fot the instacne (NO_KEY) if failed
	 */
	private native int pcap_open_live(String theInter, int buffsize, int promisc, int msec);

	/**
	 * @return the last error in pcap lib
	 */
	private native String getLastError(int key);

	/**
	 * Call dispatch for the matching key
	 * @param theKey
	 * @param theNunOfPkt - num of packets until return
	 */
	private native void pcap_dispatch(int theKey, int theNunOfPkt);

	/**
	 * get next packet
	 * @param theKey - the pcap instance key
	 * @return the byte[] array (maybe null)
	 */
	private native byte[] pcap_next(int theKey);

	/**
	 * close pcap instance.
	 */
	private native void pcap_close(int theKey);

	/**
	 * Set filter for instance
	 * @param theKey - the instacne key
	 * @param theFilter - the filter string (like tcpdump)
	 * @param mask - the net mask
	 * @return >0 for success and <=0 for failed.
	 */
	private native int pcap_set_filter(int theKey, String theFilter, long mask);

	/**
	 * 
	 * @param printTostd - if ture will print to std the names.
	 * @return string with the name of all devices (each on a line).
	 */
	private native String get_all_devices(boolean printTostd);

	
    /**
     * The method return the name of the first interface the pcap
     * library can locate.
     * @return name of the interface.
     * @throws NetUtilsException
     */
	public static String getInterfaceName() throws NetUtilsException
	{
		String[] allDevices = getAllInterfaces(false);
		if (allDevices != null && allDevices.length > 0)
		{
			return allDevices[0];
		}

		return null;
	}

    /**
     * getting all interfaces on the machine.
     * @param printTostd - if true will print all interfaces name to std out.
     * @return array of strings filled with the interfaces name. may return 
     *  null if no interfaces were located.
     * @throws NetUtilsException
     */
	public static String[] getAllInterfaces(boolean printTostd) throws NetUtilsException
	{
		String toReturn = getJPCapWriter().get_all_devices(printTostd);
		if (toReturn != null)
		{
			return toReturn.split("\n");
		}

		return null;
	}
}
