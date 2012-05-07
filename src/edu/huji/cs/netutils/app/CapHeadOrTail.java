package edu.huji.cs.netutils.app;

import java.io.IOException;

import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.utils.ArgsParser;

public class CapHeadOrTail
{
	private static ArgsParser getParser()
	{
		ArgsParser parser = new ArgsParser();
		parser.addArg("-s", 1, "source file");
		parser.addArg("-o", 1, "target file");
		parser.addArg("-head", 1, "target file");
		parser.addArg("-tail", 1, "target file");
		parser.addArg("-h", 0, "help");
		return parser;
	}
	
	
	
	public static void main(String[] args) throws IOException
	{
				
		ArgsParser parser = getParser();
		parser.init(args);
		CapAppUtils.printHelpStringIfHelp(parser);
		
		CaptureFileFlowAnalyzer ca = null;
		try
		{
			if (parser.hasOption("-s"))
			{
				CapAppUtils.validateFileExists(parser.getArgAsString("-s"));
			}
			ca = parser.hasOption("-s") ? new CaptureFileFlowAnalyzer(parser.getArgAsString("-s"))
					: new CaptureFileFlowAnalyzer(System.in);
		} catch (Exception e)
		{
			System.out.println("Error: " + e.getMessage());
			System.exit(-1);
		}
		
		CaptureFileWriter wr = null;
		
		try
		{
			if(parser.hasOption("-o"))
			{
				wr = new PCapFileWriter(parser.getArgAsString("-o"));
			}
			else
			{
			   wr = new PCapFileWriter(System.out);
			}
		}catch (Exception e) {
			System.out.println("Error: Failed to open output stream");
			System.out.println(e.getMessage());
			System.exit(-1);
		}
		
		
		int size = ca.getTotalNumOfPkts();
		
		int head = (parser.hasOption("-head"))?parser.getArgAsInt("-head"):size;
		int tail = (parser.hasOption("-tail"))?parser.getArgAsInt("-tail"):size;
		
		if(head > size)
		{
			System.out.println("Error: head > the total number of packets :" +size);
			System.exit(-1);
		}
		
		if(tail > size)
		{
			System.out.println("Error: tail > the total number of packets :" +size);
			System.exit(-1);
		}
		
				
		
		for(int i=1 ; i<=size ; i++)
		{
			if (i > head)
				continue;
			
			if (i <= size-tail )
				continue;
			
			wr.addPacket(ca.getPktNum(i), ca.getPktTimeStamp(i));
		}
	}
}
