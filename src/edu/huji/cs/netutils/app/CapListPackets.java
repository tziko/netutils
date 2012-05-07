package edu.huji.cs.netutils.app;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.files.pcap.PCapFileReader;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.utils.ArgsParser;

public class CapListPackets
{
	private static ArgsParser getParser()
	{
		ArgsParser parser = new ArgsParser();
		parser.addArg("-s", 1, "source file");
		parser.addArg("-o", 1, "target file");
		parser.addArg("-h", 0, "help");
		parser.addArg("-l", 1, "list packets [3,2,1]");
		return parser;
	}
	
	public static void main(String[] args) throws IOException
	{
				
		ArgsParser parser = getParser();
		parser.init(args);
		CapAppUtils.printHelpStringIfHelp(parser);
		
		PacketList l = new PacketList();
		StringBuffer errbf = new StringBuffer();
		
		if(!parser.hasOption("-l"))
		{
			System.err.println("Error: -l is mandatory");
			System.exit(-1);
		}
		
		if(!l.parse(parser.getArgAsString("-l"), errbf))
		{
			System.err.println(errbf.toString());
			System.exit(-1);
		}
		
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
		
		if(l.start <0 || l.start > ca.getTotalNumOfPkts())
		{
			System.err.println("Error: start index is out of range:"+l.start);
			System.exit(-1);
		}
		
		for(int i=0 ; i<l.list.length ; i++)
		{
			if(l.list[i] <1 || l.list[i] > ca.getTotalNumOfPkts())
			{
				System.err.println("Error: index is out of range:"+l.list[i]);
				System.exit(-1);
			}
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
		

		long timestamp =0;
		
        for(int i=1 ; i<l.start ; i++)
        {
        	wr.addPacket(ca.getPktNum(i), ca.getPktTimeStamp(i));
            timestamp = ca.getPktTimeStamp(i);	
        }
            
        for(int i=0 ; i<l.list.length ; i++)
        {
        	long ctimestamp = ca.getPktTimeStamp(l.list[i]);
        	if(ca.getPktTimeStamp(l.list[i]) < timestamp)
        	{
        		ctimestamp = timestamp + 1;
        	}
        	wr.addPacket(ca.getPktNum(l.list[i]),ctimestamp);
        	timestamp = ctimestamp;
        }
        
        for(int i= (ca.getTotalNumOfPkts() - l.end)+1 ; i<=ca.getTotalNumOfPkts() ; i++)
        {
        	wr.addPacket(ca.getPktNum(i), ca.getPktTimeStamp(i));
        }
		
	}
}

class PacketList
{
	int start = 0;
	int list[] = null;
	int end = 0;
		
	
	public PacketList()
	{}
	
	public boolean parse(String att,StringBuffer errbf)
	{
		String fields[] = att.split(",");
		if(fields.length == 0)
		{
			errbf.append("No valid list:"+att);
			return false;
		}
		
		int startidx = 0;
		int endidx = fields.length;
		
		if(fields[0].trim().endsWith(":"))
		{
			try
			{
				start = Integer.parseInt(fields[0].trim().split(":")[0]);
				startidx = 1;
			}
			catch (Exception e)
			{
				errbf.append("Error: Failed to parse field:"+fields[0]);
				return false;
			}
		}
		
		if(fields[fields.length-1].trim().startsWith(":"))
		{
			try
			{
				end = Integer.parseInt(fields[fields.length-1].trim().split(":")[1]);
				endidx = fields.length-1;
			}
			catch (Exception e)
			{
				errbf.append("Error: Failed to parse field:"+fields[0]);
				return false;
			}
		}
		
		list = new int[endidx-startidx];
		
		for(int i = startidx ; i<endidx ; i++)
		{
			try
			{
				list[i-startidx] = Integer.parseInt(fields[i].trim());
				
			}
			catch (Exception e)
			{
				errbf.append("Error: Failed to parse field:"+fields[i]);
				return false;
			}
		}

		return true;
	}
}
