package edu.huji.cs.netutils.capture.analyze;

import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.IPFactory;
import edu.huji.cs.netutils.parse.PacketSide;
import edu.huji.cs.netutils.parse.TCPPacket;

/**
 * 
 * Data structure for holding TCP flow.
 * Support easy printing of its content and iteration over its packets
 *  by the order they were recorded to the capture file.
 * 
 * @author roni bar-yanai
 *
 */
public class FlowTCP extends Flow
{
	private static final int TCP_FLOW_NO_PAYLOAD = -1;
	
	private TCPStateMachine myState = null;

	private int myFirstPayloadPktIdx = TCP_FLOW_NO_PAYLOAD;

	/**
	 * created by {@link CaptureFileFlowAnalyzer} or other utilities.
	 * @param an
	 * @param ft
	 * @param idx
	 */
	protected FlowTCP(CaptureFileFlowAnalyzer an, FiveTuple ft,int idx)
	{
		super(an, ft, idx);
		myState = new TCPStateMachine(ft);
	}

	/**
	 * called by analyzer for next packet.
	 * 
	 */
	protected void update(byte[] data, int n)
	{
		super.update(data, n);

		TCPPacket pkt = new TCPPacket(data);
		myStats.totalL4Bytes += pkt.getTotalTCPPlength();
		myState.handlePacket(pkt);
		
		if (pkt.getPayloadDataLength() > 0 && myFirstPayloadPktIdx == -1)
		{
			myFirstPayloadPktIdx = getNumOfPkts()-1;
		}

	}

	@Override
	public PacketType getFlowType()
	{
		return PacketType.TCP;
	}

	/**
	 * 
	 * @return true if flow contains full tcp handshake.
	 */
	public boolean isEstablished()
	{
		return myState.isEstablished();
	}

	/**
	 * 
	 * @param n - number of packet (starting with 1)
	 * @return TCP Packet
	 * @exception IndexOutOfBoundsException - when n is out of range.
	 */
	public TCPPacket getTCPPkt(int n)
	{
		return IPFactory.createTCPPacket(super.getPkt(n));
	}

	/**
	 * 
	 * @return true if flow has at least one packet with payload.
	 */
	public boolean isPayload()
	{
		return myFirstPayloadPktIdx >= 0;
	}

	/**
	 * 
	 * @return the number of the first packet which has payload.
	 *  (if no such packet exits will return TCP_FLOW_NO_PAYLOAD
	 */
	public int getFirstPayloadPacketNum()
	{
		return myFirstPayloadPktIdx+1;
	}
	
	/**
	 * 
	 * @return the first payload packet global number in the 
	 *   captue file.
	 */
	public int getFirstPayloadGlobalPacketNum()
	{
		return super.getPktGlobalIdx(getFirstPayloadPacketNum());
	}
	
	/**
	 * @param StringBuffer - sb
	 * print flow header (general information) as readable text.
	 */
	public void headerToReadableSting(StringBuffer sb)
	{
		super.headerToReadableSting(sb);
		sb.append("Full TCP handshake: "+isEstablished());
		sb.append('\n');
		sb.append("Payload: "+isPayload());
		sb.append('\n');
	}
	
	public void payloadToReadbleText(StringBuffer sb,int n)
	{
        int fsize = getNumOfPkts();
		
        n = (n<=0)?fsize:n;
		
		for (int i = 1; i <= fsize && i<=n; i++)
		{
			TCPPacket tcppkt = getTCPPkt(i);
			if(tcppkt.getTCPData().length == 0)
			{
				n++; // we don't count this packet
				continue;
			}
			
			PacketSide pktside =  (myFt.getMySrcIp().equals(tcppkt.getUnderlyingIPPacketBase().getSourceIP()))?PacketSide.CLIENT_TO_SERVER:PacketSide.SERVER_TO_CLIENT;
			
			sb.append("\r\n"+"Packet #"+i+" ("+getPktGlobalIdx(i)+").      Payload length=" +tcppkt.getPayloadDataLength()+".      Protocol=TCP"+"    "+pktside.toArrow()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");
			sb.append(pktside.toArrow());
			
			if (pktside.equals(PacketSide.CLIENT_TO_SERVER))
				sb.append(myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+" , "+myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+"\r\n");
			else
				sb.append(myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+" , "+myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");

			byte data[] = tcppkt.getTCPData();
			
			sb.append(new String(data));
			
			sb.append("\r\n");
		
		}
	}
	
	/**
	 * @param StringBuffer - sb
	 * print entire flow as readable text, which include information such as the direction
	 *  of the packet, important flags and payload.
	 *  @param n - number of packet to print
	 */
	public void toReadableText(StringBuffer sb,int n) 
	{
		headerToReadableSting(sb);
		
		int fsize = getNumOfPkts();
		
        n = (n<=0)?fsize:n;
		
		for (int i = 1; i <= fsize && i<=n; i++)
		{
			TCPPacket tcppkt = getTCPPkt(i); 
			PacketSide pktside =  (myFt.getMySrcIp().equals(tcppkt.getUnderlyingIPPacketBase().getSourceIP()))?PacketSide.CLIENT_TO_SERVER:PacketSide.SERVER_TO_CLIENT;
			
			sb.append("\r\n"+"Packet #"+i+" ("+getPktGlobalIdx(i)+").      Payload length=" +tcppkt.getPayloadDataLength()+".      Protocol=TCP"+"    "+pktside.toArrow()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");
			sb.append(pktside.toArrow());
			
			if (pktside.equals(PacketSide.CLIENT_TO_SERVER))
				sb.append(myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+" , "+myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+"\r\n");
			else
				sb.append(myFt.getMyDstIpAsString()+" : "+myFt.getDstPort()+" , "+myFt.getMySrcIpAsString()+" : "+myFt.getSrcPort()+"\r\n");
			sb.append("-----------------------------------------------------------------------------------\r\n");

			byte data[] = tcppkt.getTCPData();
			
			if (data.length >0)
			{
				putPayload(sb, data);
			}
			else
			{
				String tmp ="";
				if (tcppkt.isSyn())
				{
					tmp = tmp + "[Syn] ";
				}
				if (tcppkt.isFin())
				{
					tmp = tmp + "[Fin] ";
				}
				if (tcppkt.isAck())
				{
					tmp = tmp + "[Ack] ";
				}
				
				sb.append(tmp);
				
			}
			sb.append("\r\n");
		
		}

	}

}
