package edu.huji.cs.netutils.capture.analyze;

import edu.huji.cs.netutils.parse.FiveTuple;

/**
 * Data structure for saving all ARPs. 
 * All ARP's are considered as a single flow. 
 * 
 * @author roni bar-yanai
 *
 */
public class FlowArp extends Flow 
{

	public FlowArp(CaptureFileFlowAnalyzer an, FiveTuple ft) {
		super(an, ft, 0);

	}

	@Override
	public PacketType getFlowType()
	{
		return PacketType.ARP;

	}

}
