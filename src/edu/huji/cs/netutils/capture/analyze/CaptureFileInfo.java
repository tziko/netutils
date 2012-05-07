package edu.huji.cs.netutils.capture.analyze;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.utils.StopTimer;


/**
 * Class for getting basic statistics of flows.
 * 
 * 
 * @author roni bar yanai
 *
 */
public class CaptureFileInfo
{

	private Iterable<Flow> myFlowItr = null;
	
	private CaptureFileInfoStats myStats = new CaptureFileInfoStats();
	
	private String myDescription = "Flow Info";
	
	/**
	 * 
	 * @param theCFA - CaptrueFileFlowAnalyzer or other class that 
	 *  implements the iterator.
	 * @param desc
	 */
	public CaptureFileInfo(Iterable<Flow> theCFA,String desc)
	{
		myFlowItr = theCFA;
		myDescription = (desc!=null)?desc:myDescription;
		buildInfo();
	}

	/**
	 * collect statistics
	 */
	private void buildInfo()
	{
		for(Flow nf : myFlowItr)
		{
			switch(nf.getFlowType())
			{
			case TCP:
			{
				FlowTCP tcpnf = (FlowTCP) nf;
				myStats.totalTCPFlows++;
				myStats.totalTCPPkts+=tcpnf.getNumOfPkts();
				if(tcpnf.isEstablished())
				{
					myStats.totalTCPEstablishedFlows++;
				}
				break;
			}	
			case UDP:
				FlowUDP udpnf = (FlowUDP) nf;
				myStats.totalUDPFlows++;
				myStats.totalUDPPkts+=udpnf.getNumOfPkts();
				break;
			case OTHER:
				FlowIP ipnf = (FlowIP) nf;
				myStats.totalOtherFlows++;
				myStats.totalOtherPkts+=ipnf.getNumOfPkts();
				break;
			case ARP:
				myStats.totalArps+=nf.getNumOfPkts(); 
				break;
			case NONIP:
				myStats.totalNonIPs+=nf.getNumOfPkts();
			default:
				System.out.println("Got Other");
			}
		}
	}
	
	/**
	 * 
	 * @return statistics as readable string
	 */
	public String getFullStatistics()
	{
		StringBuffer buff = new StringBuffer();
		
		buff.append(myDescription+"\n");
		buff.append("-------------\n");
		buff.append("Total TCP Flows     : "+myStats.totalTCPFlows);
		buff.append('\n');
		buff.append("Total Established   : " + myStats.totalTCPEstablishedFlows);
		buff.append('\n');
		buff.append("Total TCP Packets   : " + myStats.totalTCPPkts);
		buff.append('\n');
		
		buff.append("Total UDP Flows     : " + myStats.totalUDPFlows);
		buff.append('\n');
		buff.append("Total UDP Packets   : " + myStats.totalUDPPkts);
		buff.append('\n');
		
		buff.append("Total Other Flows   : " + myStats.totalOtherFlows);
		buff.append('\n');
		
		buff.append("Total Other Packets : " + myStats.totalOtherPkts);
		buff.append('\n');
		
		buff.append("Total Arps          :"+myStats.totalArps);
		buff.append('\n');
		
		buff.append("Total Non Ip        :"+myStats.totalNonIPs);
		buff.append('\n');
		
		buff.append("Total Flows         :" + (myStats.totalTCPFlows+myStats.totalUDPFlows+myStats.totalOtherFlows));
		buff.append('\n');
		
		buff.append("Total Packtes       :" + (myStats.totalTCPPkts+myStats.totalUDPPkts+
				     myStats.totalOtherPkts+myStats.totalArps+myStats.totalNonIPs));
		
		buff.append('\n');
		return buff.toString();
	}
	

	class CaptureFileInfoStats
	{
		int totalTCPFlows = 0;
		int totalTCPEstablishedFlows = 0;
		int totalUDPFlows = 0;
		int totalOtherFlows = 0;
		
		int totalTCPPkts = 0;
		int totalUDPPkts = 0;
		int totalOtherPkts = 0;
		
		int totalArps = 0;
		int totalNonIPs = 0;
	}
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		if(args.length == 0)
		{
			System.out.println("Error: file parameter is missing");
		}
		
		StopTimer timer = new StopTimer();
		CaptureFileFlowAnalyzer fa = new CaptureFileFlowAnalyzer(args[0]);
		CaptureFileInfo info = new CaptureFileInfo(fa, "TEST");
		
		System.out.println(info.getFullStatistics());
		timer.showTimeToScreen();
	}
}
