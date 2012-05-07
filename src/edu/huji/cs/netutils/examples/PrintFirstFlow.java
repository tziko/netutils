package edu.huji.cs.netutils.examples;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.capture.analyze.Flow;

/**
 * 
 * @author roni bar-yanai
 *
 */
public class PrintFirstFlow
{
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		if(args.length<1)
		{
			System.out.println("missing file name parameter");
			System.exit(-1);
		}
		
		CaptureFileFlowAnalyzer an = new CaptureFileFlowAnalyzer(args[0]);
		Flow f = an.getFlow(1);
		StringBuffer bf = new StringBuffer();
		f.toReadableText(bf);
		System.out.println(bf.toString());
	}
}
