package edu.huji.cs.netutils.capture;

/**
 * Listener interface for pcap sniffer.<br>
 * In order to get packets the interface should be implemented
 * and registered in the JPCap object.<br>
 * 
 * @author roni bar-yanai
 */
public interface JPCapListener
{
	/**
	 * The method will be called on each packet received by the
	 * interface (packet may be filtered in filter is configured on the interface).
	 * @param thePacket
	 */
	public void processPacket(byte[] thePacket);
}
