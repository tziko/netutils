package edu.huji.cs.netutils.capture.analyze;

import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.IPFactory;
import edu.huji.cs.netutils.parse.PacketSide;
import edu.huji.cs.netutils.parse.TCPPacket;
import edu.huji.cs.netutils.parse.UDPPacket;

/**
 * Data structure for holding UDP flow.
 * Support easy printing of its content and iteration over its packets
 *  by the order they were recorded to the capture file.
 * 
 * @author roni bar-yanai
 *
 */
public class FlowUDP extends Flow
{

	/**
	 * created by capture file analyzer and other utils.
	 * @param an
	 * @param ft
	 * @param idx
	 */
	protected FlowUDP(CaptureFileFlowAnalyzer an, FiveTuple ft,int idx)
	{
		super(an, ft, idx);
	}
	
	@Override
	public PacketType getFlowType()
	{
		return PacketType.UDP;
	}
	
	/**
	 * 
	 * @param n - number in the flow
	 * @return UDP packet
	 * @exception IndexOutOfBoundsException - when n is out of range.
	 */
	public UDPPacket getUDPPkt(int n)
	{
		return IPFactory.createUDPPacket(super.getPkt(n));
	}
		
	/**
	 * print the flow into the buffer in text readable manner.
	 * @param sb - string buffer to print to
	 * @param n  - numebr of packets to print
	 */
	public void toReadableText(StringBuffer sb,int n) 
	{
		headerToReadableSting(sb);
		
		int fsize = getNumOfPkts();
		
		n = (n<=0)?fsize:n;
			
		for (int i = 1; i <= fsize && i<=n; i++)
		{
			UDPPacket udppkt = getUDPPkt(i); 
			PacketSide pktside = (myFt.getMySrcIp().equals(udppkt.getUnderlyingIPPacketBase().getSourceIP()))?PacketSide.CLIENT_TO_SERVER:PacketSide.SERVER_TO_CLIENT;
			System.out.println("An:"+getPktGlobalIdx(i));
			sb.append("\r\n"+"Packet #"+i+" ("+getPktGlobalIdx(i)+").      Payload length=" +udppkt.getUDPDataLength()+".      Protocol=UDP"+"    "+pktside.toArrow()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");
			sb.append(pktside.toArrow());
			
			if (pktside.equals(PacketSide.CLIENT_TO_SERVER))
				sb.append(myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+" , "+myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+"\r\n");
			else
				sb.append(myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+" , "+myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");

			byte data[] = udppkt.getUDPData();
			
			if (data.length >0)
			{
				putPayload(sb, data);
			}
			sb.append("\r\n");
		}
	}
	
	public void payloadToReadbleText(StringBuffer sb,int n)
	{
        int fsize = getNumOfPkts();
		
        n = (n<=0)?fsize:n;
		
		for (int i = 1; i <= fsize && i<=n; i++)
		{
			UDPPacket udppkt = getUDPPkt(i); 
			if(udppkt.getUDPData().length == 0)
			{
				n++; // we don't count this packet
				continue;
			}
			
			PacketSide pktside =  (myFt.getMySrcIp().equals(udppkt.getUnderlyingIPPacketBase().getSourceIP()))?PacketSide.CLIENT_TO_SERVER:PacketSide.SERVER_TO_CLIENT;
			
			sb.append("\r\n"+"Packet #"+i+" ("+getPktGlobalIdx(i)+").      Payload length=" +udppkt.getUDPDataLength()+".      Protocol=TCP"+"    "+pktside.toArrow()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");
			sb.append(pktside.toArrow());
			
			if (pktside.equals(PacketSide.CLIENT_TO_SERVER))
				sb.append(myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+" , "+myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+"\r\n");
			else
				sb.append(myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+" , "+myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");

			byte data[] = udppkt.getUDPData();
			
			sb.append(new String(data));
			
			sb.append("\r\n");
			
			}
	}

}
