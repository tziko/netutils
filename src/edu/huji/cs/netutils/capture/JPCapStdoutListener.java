package edu.huji.cs.netutils.capture;

/**
 * Simple listener for printing packets in raw format (hex format)
 *  to the screen.
 *  
 * @author roni bar-yanai
 */
public class JPCapStdoutListener implements JPCapListener
{
    
	private static final int MAX_PACKET_SIZE = 1600;
	
	// buff for editing the text.
	private final char[] statArr = new char[MAX_PACKET_SIZE*2];
	
	/**
	 * (non-Javadoc)
	 * @see edu.huji.cs.netutils.capture.JPCapListener#processPacket(byte[])
	 */
	public void processPacket(byte[] thePacket)
	{
		System.out.println("\npacket size:"+thePacket.length+"\n");
		int idx=0;
		for(int i=0 ; i<thePacket.length ; i++)
		{
			if (i != 0 && i%4 == 0)
			{
				statArr[idx++]=' ';
    		}
			if (i != 0 && i%16 == 0)
			{
				statArr[idx++]='\n';
			}
			
			int num = 0xff & thePacket[i];

			int second1 = (num & 0x0f);
			int first1 = ((num & 0xf0) >> 4);
			
			char second  = (char) ((second1<10)?'0'+second1:'A'+second1-10); 
			char first = (char) ((first1<10)?'0'+first1:'A'+first1-10);
			
			statArr[idx++]=first;
			statArr[idx++]=second;
		}
		statArr[idx++]='\n';
		System.out.println(new String(statArr,0,idx));
    }
}
