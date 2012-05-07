package edu.huji.cs.netutils.app;

import java.io.FileOutputStream;
import java.io.OutputStream;

import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.capture.utils.FlowExtract;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.utils.ArgsParser;

public class CapFlowExtract
{
	private static ArgsParser getParser()
	{
		ArgsParser parser = new ArgsParser();
		parser.addArg("-s", 1, "source file");
		parser.addArg("-o", 1, "target file");
		parser.addArg("-f", 1, "list of flow numbers comma seperated");
		parser.addArg("-l", 1, "list of packet numbers comma seperated");
		parser.addArg("-txt", 0, "print flow to stdout as readable text");
		parser.addArg("-p", 0, "only payload (only when -txt used)");
		parser.addArg("-n",1, "number of packets to extract");
		parser.addArg("-h", 0, "help");
		
		return parser;
	}
	
	public static void validateCfg(ArgsParser parser)
	{
		if(parser.hasOption("-f") && parser.hasOption("-l"))
		{
			System.err.println("Error: -f and -l cannot be used concurrently");
			System.exit(-1);
		}
		
		
		if(!parser.hasOption("-f") && !parser.hasOption("-l"))
		{
			System.err.println("Error: -f or -l are mandatory");
			System.exit(-1);
		}
		
		if(!parser.hasOption("-txt") && parser.hasOption("-p"))
		{
			System.err.println("Error: -p can be used only with -txt");
			System.exit(-1);
		}
	}
	
	public static int[] getFlowsOrPackets(ArgsParser parser)
	{
		String s = parser.hasOption("-f")?parser.getArgAsString("-f"):parser.getArgAsString("-l");
		
		String fields[] = s.trim().split(",");
		
		int toRet[] = new int[fields.length];
		
		for(int i=0 ; i<toRet.length ; i++)
		{
			try
			{
				toRet[i] = Integer.parseInt(fields[i].trim());
			} 
			catch (Exception e) {
				System.err.println("Error: failed parse indexs :"+s+", ["+fields[i]+"]");
				System.exit(-1);
			}
		}
		
		return toRet;
	}

	public static void main(String[] args)
	{

		ArgsParser parser = getParser();
		parser.init(args);
		CapAppUtils.printHelpStringIfHelp(parser);
		
		// validate mandatory flags
		validateCfg(parser);

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

		FlowExtract fe = new FlowExtract();
		if(parser.hasOption("-n"))
		{
			fe.setLimit(parser.getArgAsInt("-n"));
		}
		fe.loadCaptureFileFlowAnalyzer(ca);
		
		int idx[] = getFlowsOrPackets(parser);
		boolean isFlow = parser.hasOption("-f");
		boolean payload = parser.hasOption("-p");
		
		if (parser.hasOption("-txt"))
		{
			OutputStream wr = null;

			try
			{
				if (parser.hasOption("-o"))
				{
					wr = new FileOutputStream(parser.getArgAsString("-o"));
				} else
				{
				    wr = System.out;
				}
				
				
				
				for(int i=0 ; i<idx.length ; i++)
				{
					if(isFlow)
					{
						if(! (fe.getTotalNumOfFlows() < idx[i]))
							
						   fe.extractFlowToOutputStream(idx[i],wr,payload);
					}
					else
					{
						if(!(ca.getTotalNumOfPkts() < idx[i]))
						 fe.extractFlowOfPacketToOutputStream(idx[i],wr,payload);
					}
				}
				
			} catch (Exception e)
			{
				System.out.println("Error: Failed to open output stream");
				System.out.println(e.getMessage());
				System.exit(-1);
			}
		}
		else
		{
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
			
			for(int i=0 ; i<idx.length ; i++)
			{
				fe.setBathMode(wr);
				try
				{
				if(isFlow)
				{
					if(! (fe.getTotalNumOfFlows() < idx[i]))
					{						
					   fe.extractFlowToCapBatch(idx[i]);
					}
				}
				else
				{
					if(!(ca.getTotalNumOfPkts() < idx[i]))
					{
					   fe.extractFlowOfPktToCapBatch(idx[i]);
					}
				}
				} catch (Exception e) {
					System.err.println("Error: Failed to write" );
					System.err.println(e.getMessage());
					break;
				}
			}
			
		}
		
	}

}
