package edu.huji.cs.netutils.examples.ping;

import edu.huji.cs.netutils.capture.JPCapICMPListener;
import edu.huji.cs.netutils.parse.ICMPPacket;
import edu.huji.cs.netutils.parse.ICMPPacketType;
import edu.huji.cs.netutils.utils.IP;

/**
 * Simple ping listener.<br>
 * The simple ping listener parse the response and prints its
 * details to the standard output.
 * 
 * @author roni bar-yanai
 */
class PingListener extends JPCapICMPListener
{
	private int myResponses = 0;
	
	private long myIP = 0;
	
	/**
	 * 
	 * @param theIp
	 */
	public PingListener(String theIp)
	{
		myIP = IP.getIPAsLong(theIp);
	}
	
	public void processPacket(ICMPPacket thePkt)
	{
		try
		{
			// check that the packet is a replay
			if (thePkt.getICMPType() == ICMPPacketType.ECHO_REPLY_TYPE)
			{
				// make sure this is a response from the correct host
				if(thePkt.getIpv4Packet().getSourceIPv4().getIPasLong() == myIP)
				{
					// parse the data
					PingData data = new PingData(thePkt.getICMPData());

					// the time took will be the current time - the time in the data arrived.
					System.out.println("got replay from " + thePkt.getIpv4Packet().getSourceIPv4().getAsReadableString() + ",time = " + (System.currentTimeMillis() - data.time) + " msec , ttl = " + thePkt.getIpv4Packet().getTTL());
					myResponses++;
				}
			}
		}
		catch (RuntimeException e)
		{
			e.printStackTrace();
		}

	}
	
	/**
	 * 
	 * @return number of responses.
	 */
	public int getTotalResponses()
	{
		return myResponses;
	}

}