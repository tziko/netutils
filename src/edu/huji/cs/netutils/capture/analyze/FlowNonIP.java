package edu.huji.cs.netutils.capture.analyze;

import edu.huji.cs.netutils.parse.FiveTuple;

/**
 * Data structure for holding all non IP packet, which are considered as 
 *  a single flow.
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class FlowNonIP extends Flow
{

	/**
	 * created by {@link CaptureFileFlowAnalyzer}
	 * @param an
	 * @param ft
	 */
	protected FlowNonIP(CaptureFileFlowAnalyzer an, FiveTuple ft) 
	{
		super(an, ft, 0);
	}

	@Override
	public PacketType getFlowType()
	{
		return PacketType.NONIP;
	}

}
