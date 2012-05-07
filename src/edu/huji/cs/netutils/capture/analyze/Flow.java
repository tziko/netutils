package edu.huji.cs.netutils.capture.analyze;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;

import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.utils.ByteUtils;

/**
 * Single flow data.
 * The class support easy access for flow specific data, such as
 *  number of packets, is established (TCP), get specific packet,...etc.
 *  
 
 * @author roni bar yanai
 *
 */
public abstract class Flow implements Iterable<byte[]>
{
	
	private static final String FLOW_PRINT_PADDING_STRING = "                                                                                                                                                                                            ";
	
	protected CaptureFileFlowAnalyzer myCaptureFileAnalyzer = null;
	
	protected ArrayList<Integer> myPktIdxList = new ArrayList<Integer>();
	
	protected FlowDataStatistics myStats = new FlowDataStatistics();
	
	protected FiveTuple myFt = null;
	
	// flow number in capture file
	protected int myFlowIdx = 0;
	
	/**
	 * Create Flow
	 * @param an - pointer to capture file analyzer
	 * @param ft - five tuple (can be null when non relevant)
	 * @param idx TODO
	 */
	public Flow(CaptureFileFlowAnalyzer an, FiveTuple ft, int idx)
	{
		myCaptureFileAnalyzer = an;
		myFt = ft;
		myFlowIdx = idx;
	}
	
	/**
	 * Called from the cap analyzer on each packet that belongs
	 *  to this flows.
	 * @param data - the packet as raw byte array.
	 * @param n    - the packet number in the capture file
	 */
	protected void update(byte[] data,int n)
	{
		myPktIdxList.add(n);
		myStats.totalPkts++;
		myStats.totalBytes+=data.length;
	}

	protected class FlowDataStatistics
	{
		private int totalPkts = 0;
		private int totalBytes = 0;
		int totalL4Bytes = 0;
	}
	
	/**
	 * flow packets iterator
	 */
	public Iterator<byte[]> iterator()
	{
		return new FlowPacketIterator();
	}
	
	/**
	 * 
	 * @return Flow type (TCP,UDP,..etc)
	 */
	public abstract PacketType getFlowType();
	
	public byte[] getPkt(int n)
	{
		if (n<1 || n>myPktIdxList.size())
		{
			throw new IndexOutOfBoundsException("Packey index:"+n);
		}
		
		return myCaptureFileAnalyzer.getPktNum(myPktIdxList.get(n-1)+1);
	}
	
	/**
     *
	 * @param n - packet number in the flow starting with 1.
	 * @return the packet time stamp (from the capture).
	 */
	public long getPktTimeStamp(int n)
	{
		if (n<1 || n>myPktIdxList.size())
		{
			throw new IndexOutOfBoundsException("Packey index:"+n);
		}
		
		return myCaptureFileAnalyzer.getPktTimeStamp(myPktIdxList.get(n-1)+1);
	}
	
	/**
	 * 
	 * @param n - packet number in flow starting with 1
	 * @return - the packet global index in capture file.
	 */
	public int getPktGlobalIdx(int n)
	{
		if (n<1 || n>myPktIdxList.size())
		{
			throw new IndexOutOfBoundsException("Packey index:"+n);
		}
		
		return myPktIdxList.get(n-1)+1;
	}

	/**
	 * 
	 * @return flow five tuple
	 */
	public FiveTuple getMyFt()
	{
		return myFt;
	}
	
	/**
	 * 
	 * @return the flow total number of packets 
	 */
	public int getNumOfPkts()
	{
		return myPktIdxList.size();
	}
	
	/**
	 * 
	 * @return true if flow contains full tcp handshake or udp flow and 
	 *   false otherwise.
	 */
	public boolean isEstablished()
	{
		return true;
	}
	
	/**
	 * prints the data (usually packet payload) into the string buffer in 
	 *   a readable way for example:
	 *   11 0E 86 20   - 48 A3 A4 AE   - 00 8A 00 BB   - 00 00 20 46      ... H......... F  - 
     *   44 46 45 45   - 49 45 42 46   - 4A 45 42 46   - 41 46 41 43      DFEEIEBFJEBFAFAC  - 
	 * @param sb   - string buffer to append
	 * @param data - the data (non null)
	 */
	protected void putPayload(StringBuffer sb,byte data[])
	{
		int chunk = 16;
		int padding = 70;
		
		ByteUtils byteutils = new ByteUtils();
	
		if (data.length >0)
		{
			for (int j = 0; j < data.length; )
			{
				int size = (j+chunk);
				size = (size>data.length)?data.length:size;
				String tmp = byteutils.getAsString(data,j,size,chunk);
				tmp = (tmp.length() < padding)?tmp+getPaddString(padding-tmp.length()-(j==0?6:0)):tmp;
				sb.append(tmp);
				tmp = new String(data,j,size-j);
				tmp = tmp.replaceAll("\r",".");
				tmp = tmp.replaceAll("\n",".");
				tmp = tmp.replaceAll("\t",".");
				tmp = tmp.replaceAll("[^\\p{Print}]",".");
				sb.append(" "+tmp.trim());
				j+=chunk;
			}
		}
		sb.append("\r\n");
	}
	
	/**
	 * Print the packet as a readable string.
	 * Each specific flow type should have it own implementation 
	 * @param sb - string buffer
	 */
	public void toReadableText(StringBuffer sb) 
	{
		toReadableText(sb,0);
	}
	
	/**
	 * Print the packet as a readable string.
	 * Each specific flow type should have it own implementation 
	 * @param sb - string buffer
	 * @param n  - number of packets to print
	 */
	public void toReadableText(StringBuffer sb,int n) 
	{
		int fsize = getNumOfPkts();
		
        n = (n<=0)?fsize:n;
		
		for (int i = 1; i <= fsize && i<=n; i++)
		{
			
			sb.append("\r\n"+"Packet #"+i+" ("+getPktGlobalIdx(i)+").      \r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");
			
			byte data[] = getPkt(i);
			
			putPayload(sb, data);
			
		}
	}
	
	public void payloadToReadbleText(StringBuffer sb, int n)
	{
        int fsize = getNumOfPkts();
		n = (n<=0)?fsize:n;
		
		for (int i = 1; i <= fsize && i<=n; i++)
		{
			
			sb.append("\r\n"+"Packet #"+i+" ("+getPktGlobalIdx(i)+").      \r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");
			
			byte data[] = getPkt(i);
			
			sb.append(new String(data));
			
			sb.append("\n");
		}
	}
	
	public void headerToReadableSting(StringBuffer sb)
	{
		sb.append("Flow #"+(myFlowIdx+1));
		sb.append('\n');
		sb.append("Total packets: "+getNumOfPkts());
		sb.append('\n');
	}
	
	/**
	 * write flow to capture file writer
	 * @param wr
	 * @param n - number of packets to write
	 * @throws IOException
	 */
	public void writeToCaptureFile(CaptureFileWriter wr,int n) throws IOException
	{
		int size = getNumOfPkts();
		
		n = (n<=0)?size:n;
		
		for(int i = 1 ; i<=size && i<=n ; i++)
		{
			wr.addPacket(getPkt(i), getPktTimeStamp(i));
		}
	}
	
	/**
	 * write flow to capture file writer
	 * @param wr
	 * @throws IOException
	 */
	public void writeToCaptureFile(CaptureFileWriter wr) throws IOException
	{
		writeToCaptureFile(wr,0);
	}
	
 	/**
 	 * Internal packets iterator.
 	 * 
 	 */
	class FlowPacketIterator implements Iterator<byte[]>
	{
		private Iterator<Integer> myItr = null;
		
		private FlowPacketIterator()
		{
			myItr = myPktIdxList.iterator();
		}
		
		@Override
		public boolean hasNext()
		{
			return myItr.hasNext();
		}

		@Override
		public byte[] next()
		{
			int n = myItr.next();
			return myCaptureFileAnalyzer.getPktNum(n);
		}

		@Override
		public void remove()
		{
			// TODO Auto-generated method stub
			
		}
		
	}
	
	/*
	 * return the padding needed for formated print
	 */
	protected static String getPaddString(int size)
	{
		if (size < FLOW_PRINT_PADDING_STRING.length())
			return FLOW_PRINT_PADDING_STRING.substring(0,size);

		String toReturn ="";
		for (int i = 0; i < size; i++)
		{
			toReturn = toReturn+" ";
		}
		return toReturn;
	}
	
	/**
	 * 
	 * @return the flow number in the capture file
	 */
	public int getFlowNum()
	{
		return myCaptureFileAnalyzer.getFlowNum(myFt);
	}
	
	/**
	 * 
	 * @return total number of bytes
	 */
	public long getTotalNumberOfBytes()
	{
		return myStats.totalBytes;
	}
}
