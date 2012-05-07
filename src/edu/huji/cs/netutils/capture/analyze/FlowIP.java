package edu.huji.cs.netutils.capture.analyze;

import edu.huji.cs.netutils.parse.FiveTuple;

/**
 * Data structure for handling non TCP/UDP and other future specific L4 protocols.
 * The flow is identified by its source/destination/protocol
 * 
 * @author roni bar-yanai
 *
 */
public class FlowIP extends Flow
{
	/**
	 * created by {@link CaptureFileFlowAnalyzer}
	 * @param an
	 * @param ft
	 * @param idx
	 */
	protected FlowIP(CaptureFileFlowAnalyzer an, FiveTuple ft,int idx)
	{
		super(an, ft, idx);
	}

	@Override
	public PacketType getFlowType()
	{
		return PacketType.OTHER;
	}
	
	

}
