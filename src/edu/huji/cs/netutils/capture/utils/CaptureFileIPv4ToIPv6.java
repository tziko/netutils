package edu.huji.cs.netutils.capture.utils;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.build.EthernetFrameBuilder;
import edu.huji.cs.netutils.build.IPv6PacketBuilder;
import edu.huji.cs.netutils.build.MACAddress;
import edu.huji.cs.netutils.build.TCPPacketBuilder;
import edu.huji.cs.netutils.build.UDPPacketBuilder;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.parse.EthernetFrame;
import edu.huji.cs.netutils.parse.IPPacketType;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.parse.IPv4Packet;
import edu.huji.cs.netutils.parse.IPv6Address;
import edu.huji.cs.netutils.parse.TCPPacket;
import edu.huji.cs.netutils.parse.TCPPacketIpv4;
import edu.huji.cs.netutils.parse.UDPPacket;
import edu.huji.cs.netutils.parse.UDPPacketIpv4;
import edu.huji.cs.netutils.utils.IP;

/**
 * Utility for converting capture files or single packets objects
 *  of TCP/UDP over IPv4 into TCP/UDP over ipv6. 
 * 
 *  The user can supply its own method for converting IPv4 into IPv6.
 *  The default is just to multiple the IPv4 address 4 times.
 *  
 *  As IPv4 and IPv6 don't share all fields, only matching fields are copied.
 *  The user can change it further using the returned IPv6 packet (for example,
 *   adding extensions)
 * 
 * IP fragments are not supported.
 * 
 * @author roni bar-yanai
 *
 */
public class CaptureFileIPv4ToIPv6
{
	// Default IP conversion
	private static final IPv4AddressToIPv6AddressConvert CAPTURE_DEFAULT_CONVERT = new IPv4AddressToIPv6AddressConvert()
	{
		
		@Override
		public IPv6Address convert(IPv4Address theIPaddr)
		{
			return IP.convertIPv4ToIPv6(theIPaddr);
		}
	};  
	
	
	/**
	 * convert TCP packet over IPv4 into TCP packet over IPv6.
	 * @param theTcppkt
	 * @return converted packet
	 * @throws NetUtilsException 
	 */
	public static TCPPacket convertTCPIPv4toIPv6(TCPPacketIpv4 theTcppkt) throws NetUtilsException
	{
		return convertTCPIPv4toIPv6(theTcppkt, CAPTURE_DEFAULT_CONVERT);
	}
	
	/**
	 * Convert TCP packet over IPv4 into TCP over IPv6.
	 * 
	 * @param theTcppkt
	 * @param convert - the IPv4 address into IPv6 address convertor.
	 * @return 
	 * @throws NetUtilsException 
	 */
	public static TCPPacket convertTCPIPv4toIPv6(TCPPacketIpv4 theTcppkt,IPv4AddressToIPv6AddressConvert convert) throws NetUtilsException
	{
		EthernetFrameBuilder frame = new EthernetFrameBuilder();
		frame.setDstMac(new MACAddress(theTcppkt.getDstMacByteArray()));
		frame.setSrcMac(new MACAddress(theTcppkt.getSrcMacByteArray()));
		
		IPv6PacketBuilder ipv6Builder = new IPv6PacketBuilder();
		ipv6Builder.setDstIP(convert.convert((IPv4Address) theTcppkt.getUnderlyingIPPacketBase().getDestinationIP()));
		ipv6Builder.setSrcIp(convert.convert((IPv4Address) theTcppkt.getUnderlyingIPPacketBase().getSourceIP()));
		
		TCPPacketBuilder tcpBuilder = new TCPPacketBuilder();
		tcpBuilder.setFlags(theTcppkt.getAllFlags());
		tcpBuilder.setDstPort(theTcppkt.getDestinationPort());
		tcpBuilder.setSrcPort(theTcppkt.getSourcePort());
		tcpBuilder.setSeqNum(theTcppkt.getSequenceNumber());
		tcpBuilder.setAckNum(theTcppkt.getAcknowledgmentNumber());
		tcpBuilder.setWindowSize(theTcppkt.getWindowSize());
		tcpBuilder.setPayload(theTcppkt.getTCPData());
		tcpBuilder.setOptions(theTcppkt.getTcpOptions());
		
		ipv6Builder.addL4Buider(tcpBuilder);
		frame.addL3Buider(ipv6Builder);
		
		return tcpBuilder.createTCPPacket();
	}
	
	/**
	 * convert UDP packet over IPv4 into UDP packet over IPv6.
	 * @param theTcppkt - the IPv4 address into IPv6 address convertor.
	 * @return converted packet
	 * @throws NetUtilsException 
	 *
	 */
	public static UDPPacket convertUDPIPv4toIPv6(UDPPacketIpv4 theUDPpkt) throws NetUtilsException
	{
		return convertUDPIPv4toIPv6(theUDPpkt,CAPTURE_DEFAULT_CONVERT);
	}
	
	/**
	 * convert UDP packet over IPv4 into UDP packet over IPv6.
	 * @param theUDPpkt
	 * @param convert
	 * @return
	 * @throws NetUtilsException 
	 */
	public static UDPPacket convertUDPIPv4toIPv6(UDPPacketIpv4 theUDPpkt,IPv4AddressToIPv6AddressConvert convert) throws NetUtilsException
	{
		EthernetFrameBuilder frame = new EthernetFrameBuilder();
		frame.setDstMac(new MACAddress(theUDPpkt.getDstMacByteArray()));
		frame.setSrcMac(new MACAddress(theUDPpkt.getSrcMacByteArray()));
		
		IPv6PacketBuilder ipv6Builder = new IPv6PacketBuilder();
		ipv6Builder.setDstIP(convert.convert((IPv4Address) theUDPpkt.getUnderlyingIPPacketBase().getDestinationIP()));
		ipv6Builder.setSrcIp(convert.convert((IPv4Address) theUDPpkt.getUnderlyingIPPacketBase().getSourceIP()));
		
		UDPPacketBuilder udpBuilder = new UDPPacketBuilder();
		udpBuilder.setDstPort(theUDPpkt.getDestinationPort());
		udpBuilder.setSrcPort(theUDPpkt.getSourcePort());
		
		udpBuilder.setPayload(theUDPpkt.getUDPData());
			
		ipv6Builder.addL4Buider(udpBuilder);
		frame.addL3Buider(ipv6Builder);
		
		return udpBuilder.createUDPPacket();
	}
	
	/**
	 * Convert capture file into IPv6.
	 * 
	 * Only TCP and UDP are converted and IP fragment are not supported.
	 * All non supported packets are copied as is into the new generated file.
	 * 
	 * (use default IP address convertor)
	 * 
	 * @param srcFileName
	 * @param dstFileName
	 * @throws IOException
	 * @throws NetUtilsException
	 */
	public static void convertCpatureToIPv6(String srcFileName, String dstFileName) throws IOException, NetUtilsException
	{
		convertCpatureToIPv6(srcFileName,dstFileName, CAPTURE_DEFAULT_CONVERT);
	}
	
	/**
	 * Convert IPv4 packet to matching IPv6 packet.
	 * If packet is fragmented or non IP then returns the same buffer.
	 * 
	 * @param buff - packet as byte array.
	 * @return converted packet as byte array.
	 * 
	 * @throws NetUtilsException
	 */
	public static byte[] convertToIPv6(byte[] buff) throws NetUtilsException
	{
		if (!EthernetFrame.statIsIpv4Packet(buff))
		{
			return buff;
		}

		int proto = IPv4Packet.getIpProtocolType(buff);

		//skip fragment for now.
		if (IPv4Packet.isFragment(buff))
		{
			return buff;
		}
		
		switch (proto)
		{
		case IPPacketType.TCP:
		{	
			TCPPacketIpv4 tcppkt = new TCPPacketIpv4(buff);
			TCPPacket pkt = convertTCPIPv4toIPv6(tcppkt);
								
			return pkt.getRawBytes();
		}
		case IPPacketType.UDP:
		{
			UDPPacketIpv4 udppkt = new UDPPacketIpv4(buff);
			UDPPacket pkt = convertUDPIPv4toIPv6(udppkt);
			
			return pkt.getRawBytes();
		}
		// non tcp and udp we save it as is.
		default:
			return buff;
		}
	}
	
	/**
	 * Convert capture file into IPv6.
	 * 
	 * Only TCP and UDP are converted and IP fragment are not supported.
	 * All non supported packets are copied as is into the new generated file.
	 * 
	 * 
	 * 
	 * @param srcFileName
	 * @param dstFileName
	 * @param convert -  the IPv4 address into IPv6 address convertor.
	 * @throws IOException
	 * @throws NetUtilsException
	 */
	public static void convertCpatureToIPv6(String srcFileName, String dstFileName, IPv4AddressToIPv6AddressConvert convert) throws IOException,
			NetUtilsException
	{
		
		IPConvertCounters counter = new IPConvertCounters();
		
		CaptureFileReader rd = CaptureFileFactory.tryToCreateCaprtueFileReader(srcFileName);
		
		CaptureFileWriter wr = new PCapFileWriter(dstFileName);
		
		byte[] buff = null;
		
		try
		{
			while ((buff = rd.ReadNextPacket()) != null)
			{
				
				counter.myTotalPkts++;
				// if it is not an IP packet then skip it
				if (!EthernetFrame.statIsIpv4Packet(buff))
				{
					wr.addPacket(buff, rd.getTimeStamp());
					continue;
				}

				int proto = IPv4Packet.getIpProtocolType(buff);
		
				//skip fragment for now.
				if (IPv4Packet.isFragment(buff))
				{
					counter.myTotalFrag++;
					wr.addPacket(buff, rd.getTimeStamp());
					continue;
				}
				
				switch (proto)
				{
				case IPPacketType.TCP:
				{	
					TCPPacketIpv4 tcppkt = new TCPPacketIpv4(buff);
					TCPPacket pkt = convertTCPIPv4toIPv6(tcppkt);
										
					wr.addPacket(pkt.getRawBytes(), rd.getTimeStamp());
					counter.myTotalTcp++;
					break;
				}
				case IPPacketType.UDP:
				{
					UDPPacketIpv4 udppkt = new UDPPacketIpv4(buff);
					UDPPacket pkt = convertUDPIPv4toIPv6(udppkt);
					
					wr.addPacket(pkt.getRawBytes(), rd.getTimeStamp());
					counter.myTotalUdp++;
					break;
				}
				// non tcp and udp we save it as is.
				default:
					wr.addPacket(buff, rd.getTimeStamp());
				}
			}
		} catch (Exception e)
		{
			e.printStackTrace();
		}

		wr.close();
		System.out.println("File Convereted:" + dstFileName);
		System.out.println(counter);
	}

	/**
	 * internal statistics
	 * 
	 * @author roni bar-yanai
	 *
	 */
	static class IPConvertCounters
	{
		public int myTotalPkts = 0;
		public int myTotalTcp = 0;
		public int myTotalUdp = 0;
		public int myTotalFrag = 0;

		@Override
		public String toString()
		{
			StringBuffer buff = new StringBuffer();
			buff.append("Total Pkts        : "+myTotalPkts);
			buff.append('\n');
			buff.append("Total TCP Pkts    : "+myTotalTcp);
			buff.append('\n');
			buff.append("Total UDP Pkts    : "+myTotalUdp);
			buff.append('\n');
			buff.append("Total IP frag Pkts: "+myTotalFrag);
			buff.append('\n');
			
			return buff.toString();
		}
	}
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		convertCpatureToIPv6("c:\\tmp\\ftp.erf", "c:\\tmp\\roni.cap");
	}

}
