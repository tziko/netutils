package edu.huji.cs.netutils.app;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.capture.analyze.Flow;
import edu.huji.cs.netutils.utils.ArgsParser;

public class CapInfo
{
	
	private static ArgsParser getParser()
	{
		ArgsParser parser = new ArgsParser();
		parser.addArg("-tuples", 0, "show all tunples");
		
		return parser;
	}
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		CapAppUtils.validateParamLength(args, 1, " [cap file name]");
		CapAppUtils.validateFileExists(args[0]);
		
		ArgsParser parser = getParser();
		parser.init(args);
		
		CaptureFileFlowAnalyzer ca = new CaptureFileFlowAnalyzer(args[0]);
		
		System.out.println("Total number of packets: "+ca.getTotalNumOfPkts());
		System.out.println("Total number of flows  : "+ca.getNumberOfFlows());
		
		int tcp = 0;
		int udp = 0;
		int other = 0;
		
		boolean showtuples = parser.hasOption("-tuples");
		
		for(Flow next : ca)
		{
			switch(next.getFlowType())
			{
			case TCP:
				tcp++;
				if (showtuples)
				{
					System.out.println(next.getMyFt().oneLineReadbleString());
				}
				break;
			case UDP:
				udp++;
				if (showtuples)
				{
					System.out.println(next.getMyFt().oneLineReadbleString());
				}
				break;
			default:
				other++;
			}
		}
		
		if (!showtuples)
		{
			System.out.println("Total number of TCP flows  : "+tcp);
			System.out.println("Total number of UDP flows  : "+udp);
		}
		
	}

}
