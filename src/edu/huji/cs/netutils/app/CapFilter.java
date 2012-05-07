package edu.huji.cs.netutils.app;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.files.pcap.PCapFileReader;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.utils.ArgsParser;

public class CapFilter
{
	private static ArgsParser getParser()
	{
		ArgsParser parser = new ArgsParser();
		parser.addArg("-s", 1, "source file");
		parser.addArg("-o", 1, "target file");
		parser.addArg("-tcp", 0, "only TCP");
		parser.addArg("-udp", 0, "only UDP");
		parser.addArg("-h", 0, "help");
		return parser;
	}
	
	public static void main(String[] args) throws IOException
	{
				
		ArgsParser parser = getParser();
		parser.init(args);
		CapAppUtils.printHelpStringIfHelp(parser);
		
		CaptureFileReader rd = null;
		try
		{
		  if (parser.hasOption("-s"))
		  {
			  CapAppUtils.validateFileExists(parser.getArgAsString("-s"));
		  }
		  rd = parser.hasOption("-s")?CaptureFileFactory.tryToCreateCaprtueFileReader(parser.getArgAsString("-s")):new PCapFileReader(System.in);
		}
		catch (Exception e) {
			System.out.println("Error: "+e.getMessage());
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
		
		
		
		boolean isTcp = parser.hasOption("-tcp");
		boolean isUdp = parser.hasOption("-udp");
		
		CaptureIterator ir = new CaptureIterator(rd);
		while(ir.hasNext())
		{
			byte data[] = ir.next();
			try
			{
				FiveTuple ft = new FiveTuple(data);
				if(isTcp && ft.isTCP())
				{
					wr.addPacket(data, rd.getTimeStamp());
				}
				else if (isUdp && ft.isUDP())
				{
					wr.addPacket(data, rd.getTimeStamp());
				}
			} catch (NetUtilsException e)
			{
				// frags or none ip, skip
				continue;
			}
		}
				
	}
	
	

}
