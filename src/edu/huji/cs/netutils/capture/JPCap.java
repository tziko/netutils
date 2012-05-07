package edu.huji.cs.netutils.capture;

import java.util.ArrayList;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.impl.JPCapKey;
import edu.huji.cs.netutils.capture.impl.JPCapWraper;
import edu.huji.cs.netutils.utils.IP;

/**
 * The class implement an Ethernet sniffer.<br>
 * The sniffer can bounded to one of the interfaces and receive all packets
 * (may be filtered by tcpdump language filter).<br>
 * The packet will be dispatched to the registered JPcapListener.<br>
 * 
 * @author roni bar-yanai
 */
public class JPCap
{
	/**
	 * time to wait for sniffer to end.
	 */
	private static final long MAX_TIME_TO_WAIT_FOR_STOP = 10000;

	private static final int DEFAULT_CHUNKS = 10;

	/*
	 * the native code is in c (not c++), 
	 * each instance is identified by its key. 
	 */
	private JPCapKey myKey = null;

	/**
	 * the bounded interface name
	 */
	private String myInterface = null;

	/**
	 * holds all registered listeners.
	 */
	private ArrayList<JPCapListener> myListener = new ArrayList<JPCapListener>();

	/**
	 * the native wrapper
	 */
	private JPCapWraper myJpcapWrp = null;

	// self reference for internal listening thread.
	private JPCap mySelfRef = null;

	/*
	 * will hold the last fail reason
	 */
	private String myFailReason = null;

	/**
	 * internal thread that will do the actual listening
	 */
	private InernalThread myInThread = null;

	/**
	 * the sniffer filter
	 */
	private String myToCfgFilter = null;

	/**
	 * the filter netmask
	 */
	private long myToCfgFilterNetmask = -1;

	/**
	 * the interface ip address.
	 */
	private String myIp = null;

	// for internal initialization usage
	private boolean _isStarted = false;

	/**
	 * create jpcap instance
	 * @param theInterface - the interface name or ip.
	 * @throws NetUtilsException 
	 */
	public JPCap(String theInterface) throws NetUtilsException
	{
		if(IP.isValidIp(theInterface))
		{
			JPCapInterface intArr [] = JPCap.getAllIntefacesNames();
			boolean found = false;
			for( JPCapInterface next : intArr)
			{
				if(next.getIp().equals(theInterface))
				{
					found = true;
					myInterface = next.getName();
					break;
				}
			}
			if(!found)
			{
				throw new NetUtilsException("Interface with IP:"+theInterface+" couldn't be found");
			}
		}
		else
		{
			myInterface = theInterface;
		}
		mySelfRef = this;
		myJpcapWrp = JPCapWraper.getJPCapWriter();
	}

	/**
	 * create jpcap instance
	 * @param theInterface - inteface object ( returned by getAllInterfacs())
	 * @throws NetUtilsException 
	 */
	public JPCap(JPCapInterface theInterface) throws NetUtilsException
	{
		this(theInterface.getName());
		myIp = theInterface.getIp();
	}

	/**
	 * create new instance.
	 * will try to bound to the first interface located.
	 * @throws NetUtilsException - if no interface was found
	 */
	public JPCap() throws NetUtilsException
	{
		JPCapInterface[] all = getAllIntefacesNames();
		if (all == null || all.length == 0)
		{
			throw new NetUtilsException("Couldn't find suitable interface ");
		}

		myInterface = all[0].getName();
		myIp = all[0].getIp();
		mySelfRef = this;
		myJpcapWrp = JPCapWraper.getJPCapWriter();
	}

	/**
	 * start sniffing.
	 * All packets on the bounded interfaces will be handled by
	 * the listeners.
	 * 
	 * @throws NetUtilsException
	 */
	public synchronized void startJPcap() throws NetUtilsException
	{
		if (_isStarted)
		{
			return;
		}
		
		// open the c lib pcap
		myKey = myJpcapWrp.pcap_open_live(myInterface);
		
		// if we have a filter (tcpdump the add it to the c pcap)
		if (myToCfgFilter != null)
		{
			if ( myJpcapWrp.setFilter(this, myToCfgFilter, myToCfgFilterNetmask) == false)
				throw new NetUtilsException("Got illegal sniffing filter : "+myToCfgFilter);
		}
		
		// start internal thread for listening
		myInThread = new InernalThread();
		myInThread.start();
		_isStarted = true;
	}

	/**
	 * stop sniffing.
	 * 
	 */
	public synchronized void stopJPcap()
	{
		if (_isStarted == false) return;

		if (myInThread != null)
		{
			myInThread.stopInThread();
		}
		try
		{
			myInThread.join(MAX_TIME_TO_WAIT_FOR_STOP);
		}
		catch (InterruptedException e)
		{
		}

		//myJpcapWrp.close(this);
		_isStarted = false;
	}

	/**
	 * add listener
	 * @param theListener
	 */
	public void addListener(JPCapListener theListener)
	{
		myListener.add(theListener);
	}

	/**
	 * remove the listener if exists
	 * @param theListener
	 */
	public void removeListener(JPCapListener theListener)
	{
		myListener.remove(theListener);
	}

	/**
	 * set the sniffer filter.
	 * same syntax as tcpdup
	 * 
	 * @param theFilter - tcpdump syntax, for example "tcp port 3868 or tcp port 80"
	 * @param theSubnetMask
	 * @return true on success and false otherwise.
	 * @throws NetUtilsException
	 */
	public boolean setFilter(String theFilter, long theSubnetMask) throws NetUtilsException
	{
		if (_isStarted == false)
		{
			myToCfgFilter = theFilter;
			myToCfgFilterNetmask = theSubnetMask;
			return true;
		}

		return myJpcapWrp.setFilter(this, theFilter, theSubnetMask);
	}
	
	/**
	 * set filter
	 * @param theFilter
	 * @param theSubnet
	 * @throws NetUtilsException
	 */
	public void setFilter(String theFilter, String theSubnet) throws NetUtilsException
	{
		setFilter(theFilter,IP.getIPAsLong(theSubnet));
		
	}

	/**
	 * @return last fail reason or null.
	 */
	public String getFailReason()
	{
		return myFailReason;
	}
	
	/**
	 * @return the bounded interface ip as readable string (x.x.x.x).
	 * @throws NetUtilsException 
	 */
	public String getmyInterfaceIp() throws NetUtilsException
	{
		if (myIp == null)
		{
			JPCapInterface[] tmp = getAllIntefacesNames();
			if (tmp != null)
			{
				for (int i = 0; i < tmp.length; i++)
				{
					if (tmp[i].getName().equals(myInterface))
					{
						myIp = tmp[i].getIp();
						break;
					}
				}
			}
      	}
		return myIp;
	}
	
	/**
	 * @return the bounded interface name.
	 */
	public String getMyInterfaceName()
	{
		return myInterface;
	}

	public JPCapKey getMyJPCapKey()
	{
		return myKey;
	}

	// used in toArray method.
	final JPCapListener[] type = new JPCapListener[] {};

	/**
	 * called by the native method on each packet arrived.
	 * @param thePacket
	 */
	final public void packetArrived(byte[] thePacket)
	{
		JPCapListener[] lisArrays = (JPCapListener[]) myListener.toArray(type);

		for (int i = 0; i < lisArrays.length; i++)
		{
			lisArrays[i].processPacket(thePacket);
		}
	}

	/**
	 * Internal thread that listens for packets and dispatch them
	 * to the registered listeners.
	 * 
	 */
	class InernalThread extends Thread
	{
		private boolean stopInThread = false;

		public void run()
		{
			try
			{
				while (!stopInThread)
				{
					myJpcapWrp.pcap_dispatch(mySelfRef, DEFAULT_CHUNKS);
				}
			}
			catch (Throwable e)
			{
				myFailReason = e.getMessage();
			}
			myJpcapWrp.close(mySelfRef);
		}

		public void stopInThread()
		{
			stopInThread = true;
		}
	}

	/**
	 * @return the names of all interfaces on the machine.
	 * @throws NetUtilsException 
	 */
	public static JPCapInterface[] getAllIntefacesNames() throws NetUtilsException
	{
		String namesAndIps[] = JPCapWraper.getAllInterfaces(false);

		if (namesAndIps == null)
		{
			return new JPCapInterface[] {};
		}

		JPCapInterface[] toReturn = new JPCapInterface[namesAndIps.length / 2];

		for (int i = 0, j = 0; i < toReturn.length; i++, j += 2)
		{
			toReturn[i] = new JPCapInterface(namesAndIps[j+1].trim(), namesAndIps[j].trim());
		}

		return toReturn;
	}

	/**
	 * @return the name of the first interface found.
	 * @throws NetUtilsException 
	 * @throws NetUtilsException 
	 */
	public static String getInterfaceName() throws NetUtilsException 
	{
		JPCapInterface[] toReturn = getAllIntefacesNames();

		if (toReturn.length > 0) return toReturn[0].getName();

		return null;
	}
	
	/**
	 * @param theInterfaceName - the wanted interface name ("eth1" ...etc in linux)
	 * @return the ip configured to the interface or null if no such interface.
	 * @throws NetUtilsException 
	 */
	public static String getIpForInterface(String theInterfaceName) throws NetUtilsException
	{
		JPCapInterface all[] = getAllIntefacesNames();
		
		if (all == null || all.length == 0)
			return null;
		
		for (int i = 0; i < all.length; i++)
		{
			if (all[i].getName().equals(theInterfaceName))
				return all[i].getIp();
		}		
		return null;
	}
	
	/**
	 * 
	 * @param ip
	 * @return the interface if such exists.
	 * @throws NetUtilsException - will be thrown if no interface with that IP can be found.
	 */
	public static JPCapInterface getInterfaceByIp(String ip) throws NetUtilsException
	{
		JPCapInterface intArr [] = JPCap.getAllIntefacesNames();
		for( JPCapInterface next : intArr)
		{
			if(next.getIp().equals(ip))
			{
				return next;
			}
		}

		throw new NetUtilsException("Interface with IP:"+ip+" couldn't be found");
		
	}

	public static void main(String[] args) throws NetUtilsException
	{

		JPCap jp = new JPCap("10.10.20.23");
		
		System.out.println("Good");
		
	
	}
}
