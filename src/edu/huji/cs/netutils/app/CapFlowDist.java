package edu.huji.cs.netutils.app;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.parse.FiveTuple;

public class CapFlowDist
{
	private static final int MAX_PACKETS = 1000000;

	public static void main(String[] args) throws NetUtilsException, IOException
	{
		CapAppUtils.validateParamLength(args, 1, " [cap file name] [regexp]");
		CapAppUtils.validateFileExists(args[0]);

		CaptureFileReader rd = CaptureFileFactory.tryToCreateCaprtueFileReader(args[0]);

		CaptureIterator ir = new CaptureIterator(rd);

		HashMap<FiveTuple, Long> myFlowDist = new HashMap<FiveTuple, Long>();
		int frag = 0;
		int c = 0;
		while (ir.hasNext())
		{
			byte data[] = ir.next();
			try
			{
				FiveTuple ft = new FiveTuple(data);

				if (ft.isTCP() || ft.isUDP())
				{
					if (myFlowDist.containsKey(ft))
					{
						myFlowDist.put(ft, myFlowDist.get(ft) + 1);
					} else
					{
						myFlowDist.put(ft, 1l);
					}
					c++;
				}

			} catch (Exception e)
			{
				frag++;
			}
		}

		int udp[] = new int[MAX_PACKETS + 1];
		int tcp[] = new int[MAX_PACKETS + 1];
		
		long total = 0;
		long flows = 0;

		for (Iterator ir1 = myFlowDist.keySet().iterator(); ir1.hasNext();)
		{
			FiveTuple next = (FiveTuple) ir1.next();

			int idx = MAX_PACKETS;
			if (myFlowDist.get(next) < MAX_PACKETS)
			{
				long tmp = myFlowDist.get(next);
				idx = (int) tmp;
			}

			if (next.isTCP())
			{
				tcp[idx]++;
			} else
			{
				udp[idx]++;
			}
		}
		
		for(int i=0 ; i<tcp.length ; i++)
		{
			System.out.println(i+","+tcp[i]);
			total+=((tcp[i]+udp[i])*i);
			flows+=(tcp[i]+udp[i]);
		}
		
		System.out.println("total: "+total);
		System.out.println(c);
		System.out.println(flows);
	}

}
