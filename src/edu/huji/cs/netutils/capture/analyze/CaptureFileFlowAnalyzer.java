package edu.huji.cs.netutils.capture.analyze;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.NetUtilsFragmentException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.pcap.PCapFileReader;
import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.IPFactory;

/**
 * Capture file analyzer.
 * Capture file is being read into memory and split into flows.
 * The class provide simple information about the capture and iterators
 * for the different flows. Provide easy interface for accessing captire file in 
 *  flow abstraction and not packet. 
 *  
 * Handles only TCP,UDP, and other IP flows. all non IP's packets are regarded as single flow.
 *  Also IPv4 fragment are not supported and are collected into single "fragments flow"
 * 
 * @author roni bar-yanai
 */
public class CaptureFileFlowAnalyzer implements Iterable<Flow>
{

	private String myFileName = null;
	
	private CaptureAnalyzerStatistics myStas = new CaptureAnalyzerStatistics();
	
	private HashMap<FiveTuple, Flow> myFlowHash = new HashMap<FiveTuple, Flow>();
	private ArrayList<Flow> myFlowDataList = new ArrayList<Flow>();
	private HashMap<Integer, Flow> myPktToFlowMap = new HashMap<Integer, Flow>();
	private HashMap<FiveTuple,Integer> myFlowsNumByFt = new HashMap<FiveTuple, Integer>();
	
	private ArrayList<Long> myTimeStamps = new ArrayList<Long>();
	private ArrayList<Flow> myFlowByOrder = new ArrayList<Flow>();
	
	private ArrayList<byte[]> myPkts = new ArrayList<byte[]>();
	
	private FlowArp myArps = null;
	private FlowNonIP myNonIps = null;
	
	private FlowIPFrag myFrags = null;
	
	/**
	 * Open capture file for analyze. Capture file
	 * must be in a format supported by the netutils.
	 * 
	 * The capture file is loaded into memory and therefore 
	 * only reasonable size capture file could be handled.
	 * 
	 * @param fileName - capture file full name.
	 * @throws NetUtilsException 
	 * @throws IOException 
	 */
	public CaptureFileFlowAnalyzer(String fileName) throws IOException, NetUtilsException
	{
		myFileName = fileName;
		myArps = new FlowArp(this, null);
		myNonIps = new FlowNonIP(this, null);
		
		// tmp solution for frags
		myFrags = new FlowIPFrag(this, null);
		CaptureFileReader rd = CaptureFileFactory.tryToCreateCaprtueFileReader(myFileName);
		initialize(rd);
	}
	
	/**
	 * Open capture file for analyze. Capture file
	 * must be in a format supported by the netutils.
	 * 
	 * The capture file is loaded into memory and therefore 
	 * only reasonable size capture file could be handled.
	 * 
	 * @param fileName - capture file full name.
	 * @throws NetUtilsException 
	 * @throws IOException 
	 */
	public CaptureFileFlowAnalyzer(InputStream in) throws IOException, NetUtilsException
	{
		myArps = new FlowArp(this, null);
		myNonIps = new FlowNonIP(this, null);
		
		// tmp solution for frags
		myFrags = new FlowIPFrag(this, null);
		
		PCapFileReader rd = new PCapFileReader(in);
		initialize(rd);
	}


	/**
	 * Read capture and split it into flows.
	 * @throws IOException
	 * @throws NetUtilsException
	 */
	private void initialize(CaptureFileReader rd) throws IOException, NetUtilsException
	{
		
		byte[] nextPkt = null;

		
		while( (nextPkt = rd.ReadNextPacket()) != null)
		{
			myPkts.add(nextPkt);
			myTimeStamps.add(rd.getTimeStamp());
			
			// we handle only ipv4 packets
			if (!IPFactory.isIPPacket(nextPkt))
			{
				// all arps are treated as single flow 
				if (EthernetFrame.statIsArpPacket(nextPkt))
				{
					myArps.update(nextPkt, myStas.total);
					myPktToFlowMap.put(myStas.total, myArps);
				} 
				else 
				{
					myNonIps.update(nextPkt, myStas.total);
					myPktToFlowMap.put(myStas.total, myNonIps);
				}
				myStas.nonIp++;
				myStas.total++;
				continue;
			}
			
			handlePkt(nextPkt);
			myStas.total++;
		}
	}
	
	private void handlePkt(byte[] data) throws NetUtilsException
	{
		try
		{
		// extract flow five tuple.
		FiveTuple ft = new FiveTuple(data);
		
		// if flow already opened then update.
		if(myFlowHash.containsKey(ft))
		{
			Flow dt = myFlowHash.get(ft);
			dt.update(data,myStas.total);
			myFlowByOrder.add(dt);
            myPktToFlowMap.put(myStas.total, dt);
		} 
		else
		{
			FiveTuple newft = new FiveTuple(data);
			Flow  newfd = createFlowData(ft);
			newfd.update(data, myStas.total);
			myFlowHash.put(newft, newfd);
			myFlowDataList.add(newfd);
			myFlowByOrder.add(newfd);
			myPktToFlowMap.put(myStas.total, newfd);
			myFlowsNumByFt.put(newft,myFlowsNumByFt.size()+1);
		}
		} 
		// tmp solution for IP fragments
		catch (NetUtilsFragmentException ex)
		{
			myFrags.update(data, myStas.total);
		}
	}
	
	private Flow createFlowData(FiveTuple ft)
	{
		if (ft.isTCP())
		{
			return new FlowTCP(this,ft,myFlowDataList.size());
		}
		else if (ft.isUDP())
		{
			return new FlowUDP(this,ft,myFlowDataList.size());
		}
		else 
		{
			return new FlowIP(this,ft,myFlowDataList.size());
		}
	}

	/**
	 * 
	 * @return iterator over all flows
	 */
	public Iterator<Flow> iterator()
	{
		ArrayList<Flow> lst = new ArrayList<Flow>(myFlowDataList);
		lst.add(myArps);
		lst.add(myNonIps);
		return lst.iterator();
	}
	
	
	/**
	 * 
	 * @return the number of flows in the capture file (TCP or UDP)
	 */
	public long getNumberOfFlows()
	{
		return myFlowHash.size();
	}
	
	/**
	 * 
	 * @param n - packet number starting with 1.
	 * @return the packet
	 */
	public byte[] getPktNum(int n)
	{
		if (n<1 || n>myPkts.size())
			throw new IllegalArgumentException("packet number is out of range");
		return myPkts.get(n-1);
	}
	
	/**
	 * 
	 * @return total number packets in capture file
	 */
	public int getTotalNumOfPkts()
	{
		return myPkts.size();
	}
	
	public long getPktTimeStamp(int n)
	{
		if (n<1 || n>myPkts.size())
			throw new IllegalArgumentException("packet number is out of range");
		return myTimeStamps.get(n-1);
	}
	
	public Flow getFlow(int n)
	{
		if (n<1 || n>myFlowDataList.size())
		{
			throw new IndexOutOfBoundsException("idx"+n);
		}
		
		return myFlowDataList.get(n-1);
	}
	
	public Flow getFlowOfPkt(int n)
	{
		if (n<1 || n>myPkts.size())
		{
			throw new IndexOutOfBoundsException("idx:"+n);
		}
		
		return myPktToFlowMap.get(n-1);
	}
	
	/**
	 * return flow number in the capture file.
	 * @param theFt
	 * @return
	 */
	protected int getFlowNum(FiveTuple theFt)
	{
		return myFlowsNumByFt.get(theFt);
	}

	/**
	 * Internal statistics.
	 * 
	 */
	class CaptureAnalyzerStatistics
	{
		private int total  = 0;
		private int nonIp = 0;
	}
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		//CaptureFileFlowAnalyzer ca = new CaptureFileFlowAnalyzer("c:\\zattoo.enc");
		CaptureFileFlowAnalyzer ca = new CaptureFileFlowAnalyzer("c:\\client.enc");
		System.out.println("Total Flows:"+ca.getNumberOfFlows());
				
		for (Iterator ir = ca.iterator(); ir.hasNext();)
		{
			StringBuffer bf = new StringBuffer();
			Flow next = (Flow) ir.next();
			
			next.headerToReadableSting(bf);
			System.out.println(bf.toString());
		}
		
		System.out.println("============"+ca.getNumberOfFlows());
		
	}

	
}
