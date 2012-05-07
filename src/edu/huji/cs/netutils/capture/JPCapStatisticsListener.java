package edu.huji.cs.netutils.capture;

/**
 * Listener for counting statistics on a interface.
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class JPCapStatisticsListener implements JPCapListener {

	private int myTotalPackets = 0;
	
	/**
	 * (non-Javadoc)
	 * @see edu.huji.cs.netutils.capture.JPCapListener#processPacket(byte[])
	 */
	public void processPacket(byte[] thePacket)
	{
	
		myTotalPackets++;
	}

	/**
	 * 
	 * @return total number of packets that were recieved so far.
	 */
	public int getMyTotalPackets()
	{
		return myTotalPackets;
	}
}
