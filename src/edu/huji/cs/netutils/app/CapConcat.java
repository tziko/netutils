package edu.huji.cs.netutils.app;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.utils.CaptureFileConcat;

public class CapConcat
{
	
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		
		CaptureFileConcat concat = new CaptureFileConcat(System.out); 
		
		for(int i=0 ; i<args.length ; i++)
		{
			CapAppUtils.validateFileExists(args[0]);
			concat.appendFile(args[0]);
		}

	}
}
