package edu.huji.cs.netutils.examples;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.capture.analyze.Flow;
import edu.huji.cs.netutils.capture.analyze.FlowTCP;

/**
 * Count number of flows in capture file using the {@link CaptureFileFlowAnalyzer}
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class CountFlowsUsingAnalyzer
{

	public static void main(String[] args) throws IOException, NetUtilsException
	{
		if(args.length<1)
		{
			System.out.println("missing file name parameter");
			System.exit(-1);
		}
		
		// open analyzer
		CaptureFileFlowAnalyzer ca = new CaptureFileFlowAnalyzer(args[0]);
		
		int tcp = 0;
		int udp = 0;
		int es_tcp = 0;
	    // iterate over all flows
		for (Flow f : ca)
		{
			switch(f.getFlowType())
			{
			case TCP:
				tcp++;
				// tcp. cast to the FlowTCP object and
				// use is access methods for its establishment state.
				FlowTCP ftcp = (FlowTCP) f;
				if (ftcp.isEstablished())
					es_tcp++;
				break;
			case UDP:
				udp++;
				break;
			default:
				break;
			}
		}
		
		System.out.println("Total TCP Flows             : "+tcp);
		System.out.println("Total Established TCP Flows : "+es_tcp);
		System.out.println("Total UDP Flows             : "+udp);
		
	}
}
