package edu.huji.cs.netutils.capture;

import edu.huji.cs.netutils.parse.EthernetFrame;

/**
 * Listener for eth packets.
 *  
 *  
 * @author roni bar-yanai
 */
public abstract class JPCapEthListener implements JPCapListener
{
    private boolean _verbose = false; 
	
	/**
	 * if set to true then will print exception to screen.
	 * 
	 * @param enable
	 */
	public void setVerbose(boolean enable)
	{
		_verbose = enable;
	}
	
	/**
	 * if the packet is ethernet then will call the process method.
	 */
	final public void processPacket(byte[] thePacket)
	{
		try
		{
			processPacket(new EthernetFrame(thePacket));
		}
		catch (Exception e)
		{
			if (_verbose)
			e.printStackTrace();
		}
	}
	
	/**
	 * The method will be called on each eth packet that passed the filter.
	 * @param thePkt
	 */
	public abstract void processPacket(EthernetFrame thePkt);
  
}
