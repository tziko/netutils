package edu.huji.cs.netutils.app;

import java.io.File;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.utils.ArgsParser;

public class CapAppUtils
{
	public static void validateParamLength(String[] args, int n, String help)
	{
		if (n > args.length)
		{
			System.err.println("Error: missing parameters");
			if (help != null)
			{
				System.out.println(help);
			}
			System.exit(-1);
		}

	}

	public static void validateFileExists(String name)
	{
		if (!new File(name).exists())
		{
			System.err.println("Error: file " + name + " does not exists ");
			System.exit(-1);
		}
	}

	public static String[] getAtgsSlice(String args[], int startIdx)
	{
		if (args.length == 0 || startIdx >= args.length)
		{
			return new String[0];
		}

		String toRet[] = new String[args.length - (startIdx)];
		System.arraycopy(args, startIdx, toRet, 0, toRet.length);

		return toRet;
	}
	
	public static void conditionalSysout(boolean verb,String out)
	{
		if(verb)
		{
			System.out.println(out);
		}
	}

	public static CaptureFileReader openCaptureFileOrExit(String theFileName)
	{
		CaptureFileReader rd = null;

		try
		{
			rd = CaptureFileFactory.tryToCreateCaprtueFileReader(theFileName);
		} catch (NetUtilsException e)
		{
			System.err.println("Error: Faile to open file "+theFileName);
			System.err.println(e.getMessage());
			System.exit(-1);
		}
		
		return rd;
	}
	
	public static void printHelpStringIfHelp(ArgsParser parser)
	{
		if(parser.hasOption("-h"))
		{
			System.out.println(parser.toString());
			System.exit(0);
		}
	}

}
