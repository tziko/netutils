package edu.huji.cs.netutils.capture.analyze;

import java.io.IOException;
import java.util.LinkedList;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.IPv4Packet;
import edu.huji.cs.netutils.parse.TCPPacket;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;

/**
 * Class for completing TCP 3 way handshake 
 * The class receives a FlowDataTCP and generates the 3 way. 
 * 
 * @author roni bar-yanai
 *
 */
public class TCPFlow3WayHandshakeGen
{
	
	private FlowTCP myFlowData = null;
	
	// the 3 way handshake generated as byte array y
	private LinkedList<byte[]> myHandShakeBytes = new LinkedList<byte[]>();
	
	private long myTimeStamp = 0;
	
	/**
	 * 
	 * @param fd - TCP Flow.
	 * @throws NetUtilsException
	 * @throws IOException
	 */
	public TCPFlow3WayHandshakeGen(FlowTCP fd) throws NetUtilsException, IOException
	{
		myFlowData = fd;
		myTimeStamp = fd.getPktTimeStamp(1);
		prepare3wayHandshake();
	}

	/**
	 * 
	 * @throws NetUtilsException
	 * @throws IOException
	 */
	private void prepare3wayHandshake() throws NetUtilsException, IOException
	{
		int size = myFlowData.getNumOfPkts();
		FiveTuple ft = myFlowData.getMyFt();
		TCPPacket tcppkt = myFlowData.getTCPPkt(1);
		
		long seqsrc = tcppkt.getSequenceNumber();
		long seqdst = 0;
		for(int i=1 ; i<size ; i++)
		{
			TCPPacket next = myFlowData.getTCPPkt(i);
			if (! (next.getUnderlyingIPPacketBase().getDestinationIP().equals(ft.getMyDstIp())))
			{
				seqdst = next.getSequenceNumber();
				break;
			}
		}
				
		//TBD - adjust for ipv6
		TCPPacketIpv4 synpkPacket = new TCPPacketIpv4();
		synpkPacket.getUnderlyingIPPacketBase().setDstMacAddress(tcppkt.getDstMacByteArray());
		synpkPacket.getUnderlyingIPPacketBase().setSrcMacAddress(tcppkt.getSrcMacByteArray());
		synpkPacket.getUnderlyingIPPacketBase().setPacketType(IPv4Packet.ETHERNET_IP_PKT_TYPE);
		synpkPacket.setSyn(true);
		synpkPacket.setFiveTuple(ft);
		synpkPacket.setSequenceNum(seqsrc-1);
		synpkPacket.createPacketBytes();
		
		TCPPacketIpv4 synAckPacket = new TCPPacketIpv4();
		synAckPacket.getUnderlyingIPPacketBase().setDstMacAddress(tcppkt.getSrcMacByteArray());
		synAckPacket.getUnderlyingIPPacketBase().setSrcMacAddress(tcppkt.getDstMacByteArray());
		synAckPacket.getUnderlyingIPPacketBase().setPacketType(IPv4Packet.ETHERNET_IP_PKT_TYPE);
		synAckPacket.setSyn(true);
		synAckPacket.setAck(true);
		synAckPacket.setAckNum(seqsrc);
		synAckPacket.setFiveTuple(FiveTuple.reverseFiveTuple(ft));
		synAckPacket.setSequenceNum(seqdst-1);
		synAckPacket.createPacketBytes();
		
		TCPPacketIpv4 ackPacket = new TCPPacketIpv4();
		ackPacket.getUnderlyingIPPacketBase().setDstMacAddress(tcppkt.getDstMacByteArray());
		ackPacket.getUnderlyingIPPacketBase().setSrcMacAddress(tcppkt.getSrcMacByteArray());
		ackPacket.getUnderlyingIPPacketBase().setPacketType(IPv4Packet.ETHERNET_IP_PKT_TYPE);
		ackPacket.setAck(true);
		ackPacket.setAckNum(seqdst);
		ackPacket.setFiveTuple(ft);
		ackPacket.setSequenceNum(seqsrc);
		ackPacket.createPacketBytes();
		
		
		myHandShakeBytes.add(synpkPacket.getRawBytes());
		myHandShakeBytes.add(synAckPacket.getRawBytes());
		myHandShakeBytes.add(ackPacket.getRawBytes());
	}
	
	public void writeToFile(CaptureFileWriter wr) throws IOException
	{
		int n = -3;
		for(byte data[] : myHandShakeBytes)
		{
			wr.addPacket(data, myTimeStamp+n++);
		}
	}
	
	
}
