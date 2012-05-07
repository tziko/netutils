package edu.huji.cs.netutils.capture.analyze;

import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer.CaptureAnalyzerStatistics;
import edu.huji.cs.netutils.parse.FiveTuple;

/**
 * Data structure for collecting all IPv4 fragments.
 *  Currently there is no support and all fragment are considered as a single flow.
 *   (although the api provide tools to handle it by code)
 * 
 * @author roni bar-yanai
 *
 */
public class FlowIPFrag extends Flow
{

	/**
	 * created by {@link CaptureAnalyzerStatistics}
	 * @param an
	 * @param ft
	 */
	protected FlowIPFrag(CaptureFileFlowAnalyzer an, FiveTuple ft)
	{
		super(an, ft, 0);
	}

	@Override
	public PacketType getFlowType()
	{
		return PacketType.IPFragment;
	}

}
