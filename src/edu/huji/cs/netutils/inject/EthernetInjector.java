package edu.huji.cs.netutils.inject;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.inject.impl.JInjectKey;
import edu.huji.cs.netutils.inject.impl.JLibNetWraper;

/**
 * Class for injecting Ethernet packets.<br>
 * The user sets source and destination mac addresses together
 * with the packet type (ip for example) and the data.<br>
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class EthernetInjector
{
	// 
	private static final int ETH_MAC_LEN = 6;
	
	// c instance identifier
	private JInjectKey myKey = null;
	private JLibNetWraper myJLibNetWraper = null;
	
	private boolean _isBinded = false;
	
	/**
	 * create new instance bounded to specific network interface.
	 * @param theInterfaceName
	 * @throws NetUtilsException
	 */
	public EthernetInjector(String theInterfaceName) throws NetUtilsException
	{
		myJLibNetWraper = JLibNetWraper.getInsance(); 
		myKey = myJLibNetWraper.libnetInitLinkLayer(theInterfaceName);
		_isBinded = true;
	}
	
	/**
	 * Inject Ethernet frame. 
	 * @param srcAddr - source mac address.
	 * @param dstAddr - destination mac address.
	 * @param pktType - frame type
	 * @param thePayload - payload of the Ethernet frame.
	 * @throws NetUtilsException
	 */
	public void inject(byte[] srcAddr,byte[] dstAddr,int pktType,byte[] thePayload) throws NetUtilsException
	{
		// check if was opened successfully.
		if (_isBinded == false)
			throw new NetUtilsException("Injector wasn't bounded properly");
		
		// check all required parameters were included.
		if (srcAddr == null || dstAddr == null || thePayload == null)
			throw new NetUtilsException("Got one or more null parameters");
		
		// check mac addresses are valid.
		if (srcAddr.length < ETH_MAC_LEN || dstAddr.length < ETH_MAC_LEN)
			throw new NetUtilsException("Got illegal mac addresses");
		
		// call the c layer.
		myJLibNetWraper.libnet_build_ethernet(dstAddr,srcAddr,pktType,thePayload,myKey.getKeyAsInt());
		myJLibNetWraper.libnet_write(myKey.getKeyAsInt());
	}
	
	/**
	 * close resouces.
	 * release libnet resources.
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
	
	public static void main(String[] args) throws NetUtilsException
	{
		
			
		EthernetInjector wr = new EthernetInjector("\\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC}");
		
		//wr.libnetInitLinkLayer("\\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC}");
		
		byte[] data = new byte[1400];
		
		for (int i = 0; i < data.length; i++)
		{
			data[i] = (byte) i;
		}
		
		byte[] src = new byte[] {0x1,(byte) 0xde,(byte) 0xad,(byte) 0xbe,(byte) 0xef,0};
		byte[] dst = new byte[] {0x00,(byte) 0x0d,(byte) 0x60,(byte) 0xfd,(byte) 0xf5,(byte) 0xfc};
		
		//wr.libnet_build_ethernet(dst,src,0x800,data,0);
		long time = System.currentTimeMillis();
		//wr.libnetInitLinkLayer("\\Device\\NPF_{375BAD90-3078-460E-B382-FE46CF4D1EDC}");
		
		try
		{
			for(int i=0 ; i<8000 ; i++)
			{
			   
			   wr.inject(dst,src,0x800,data);
			   src[0]++;
        		}
		}
		catch (Exception e)
		{
		
			e.printStackTrace();
		}
		
		System.out.println("time took = "+(System.currentTimeMillis() - time));
		
		wr.releaseResource();
	}
}
