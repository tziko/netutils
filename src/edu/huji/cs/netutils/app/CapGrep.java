package edu.huji.cs.netutils.app;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;
import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.IPFactory;
import edu.huji.cs.netutils.parse.TCPPacket;
import edu.huji.cs.netutils.parse.UDPPacket;
import edu.huji.cs.netutils.utils.ArgsParser;

public class CapGrep
{
	private static ArgsParser getParser()
	{
		ArgsParser parser = new ArgsParser();

		parser.addArg("-o", 1, "output file name");
		parser.addArg("-v", 0, "verbose");
		parser.addArg("-tuples", 0, "print tuples");
		parser.addArg("-h", 0, "help");

		return parser;
	}

	public static void main(String[] args) throws IOException, NetUtilsException
	{
		CapAppUtils.validateParamLength(args, 2, " [cap file name] [regexp]");
		CapAppUtils.validateFileExists(args[0]);

		String fileName = args[0];
		String regexp = args[1];

		ArgsParser parser = getParser();
		parser.init(CapAppUtils.getAtgsSlice(args, 2));

		boolean vervbose = parser.hasOption("-v");
		if (vervbose && !parser.hasOption("-o"))
		{
			vervbose = false;
		}

		Pattern p = null;

		CapAppUtils.conditionalSysout(vervbose, "Compilng Regular Expression");

		try
		{
			p = Pattern.compile(regexp);
		} catch (PatternSyntaxException e)
		{
			System.out.println("regular expression is not valid");
			System.out.println(e.getDescription());
			System.exit(-1);
		}

		CapAppUtils.conditionalSysout(vervbose, "...Success");

		HashSet<FiveTuple> tuples = new HashSet<FiveTuple>();

		CapAppUtils.conditionalSysout(vervbose, "Open file for read");
		// pass one, collect relevant tuples.
		CaptureFileReader rd = CapAppUtils.openCaptureFileOrExit(fileName);

		CaptureIterator ir = new CaptureIterator(rd);

		int match = 0;
		int frag = 0;
		while (ir.hasNext())
		{
			byte data[] = ir.next();
			try
			{
				FiveTuple ft = new FiveTuple(data);
				byte payload[] = null;

				// first we handle only TCP and UDP
				if (ft.isTCP())
				{
					TCPPacket tcp = IPFactory.createTCPPacket(data);
					payload = tcp.getTCPData();
				} else if (ft.isUDP())
				{
					UDPPacket udp = IPFactory.createUDPPacket(data);
					payload = udp.getUDPData();
				} else
				{
					continue;
				}

				// check if we have payload
				if (payload != null && payload.length > 0)
				{
					Matcher m = p.matcher(new String(payload));
					if (m.find())
					{
						match++;
						//System.out.println(new String(payload));
						//System.out.println(ft.oneLineReadbleString());
						tuples.add(ft);
					}
				}
			} catch (Exception e)
			{
				frag++;
			}

		}

		CapAppUtils.conditionalSysout(vervbose, "Total Flow Match:" + tuples.size());

		if(tuples.size() == 0)
			System.exit(0);
		System.out.flush();
		

		if(parser.hasOption("-tuples"))
		{
			PrintStream out = (parser.hasOption("-o")) ? new PrintStream(new FileOutputStream(parser.getArgAsString("-o"))) : new PrintStream(System.out);
			for(FiveTuple next : tuples)
			{
				out.print(next.oneLineReadbleString());
			}
		}
		else
		{
			PCapFileWriter wr = (parser.hasOption("-o")) ? new PCapFileWriter(parser.getArgAsString("-o")) : new PCapFileWriter(System.out);
			rd = CapAppUtils.openCaptureFileOrExit(fileName);

			ir = new CaptureIterator(rd);
			int c = 0;
			while (ir.hasNext())
			{
				byte data[] = ir.next();
				try
				{
					FiveTuple ft = new FiveTuple(data);
					if (tuples.contains(ft))
						wr.addPacket(data, c++);
				} catch (Exception e)
				{
				}
			}
			wr.close();
		}
		CapAppUtils.conditionalSysout(vervbose, "Done");
		System.out.flush();
	}
}
