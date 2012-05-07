package edu.huji.cs.netutils.examples;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.capture.analyze.Flow;
import edu.huji.cs.netutils.capture.analyze.FlowTCP;
import edu.huji.cs.netutils.capture.analyze.PacketType;
import edu.huji.cs.netutils.capture.utils.FlowExtract;

/**
 * Example of finding flows which match certain criteria.
 * In this specific example we find HTTP flows which has the 
 *  full TCP 3-way-handshake.
 * 
 * @author roni bar-yanai
 *
 */
public class FindHTTPFlows
{

	public static void main(String[] args) throws IOException, NetUtilsException
	{
		args = new String[]{"c:\\client.enc"};
        
		// create analyzer 
		CaptureFileFlowAnalyzer ca = new CaptureFileFlowAnalyzer(args[0]);

        // regular expression pattern for HTTP.
		Pattern p = Pattern.compile("(GET|POST|HEAD|POST|DELETE|TRACE|CONNECT).*HTTP");
			
		int match = 0;
		
		// iterate flows
		for (Flow f : ca)
		{
			if (f.getFlowType() == PacketType.TCP)
			{
				FlowTCP ftcp = (FlowTCP) f;
				
				// first two conditions 
				if (ftcp.isEstablished() && ftcp.isPayload())
				{
					int n = ftcp.getFirstPayloadPacketNum();
					byte data[] = ftcp.getTCPPkt(n).getTCPData();
					
					// try to match
					Matcher m = p.matcher(new String(data));
					if (m.find())
					{
						//System.out.println("Flow #"+f.getFlowNum());
						match++;
						if(match == 1)
						{
							FlowExtract fe = new FlowExtract();
							fe.loadCaptureFileFlowAnalyzer(ca);
							fe.extractFlowToScreen(f.getFlowNum());
						}
					}
				}
			}
		}
		System.out.println("Total Flows   :"+ca.getNumberOfFlows());
		System.out.println("Total Matches :"+match);
	}
}
