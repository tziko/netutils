package edu.huji.cs.netutils.capture.utils;

import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.files.CaptureIterator;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;

/**
 * Utiltiy for squeezing capture files timestamp.
 * Reducing the total injection time when injecting by timestamps.
 * 
 * @author roni bar-yanai
 *
 */
public class CaptureFileSqueezeTime implements CaptureFileWriter
{
	private int myInterval = 1;
	
	private CaptureFileWriter myWr = null;

	private int myCounter = 0;
	
	private boolean _isopen = false;

	/**
	 * 
	 * @param theWr
	 */
	public CaptureFileSqueezeTime(CaptureFileWriter theWr)
	{
		super();
		myWr = theWr;
	}
	
	/**
	 * Create new file
	 * @param theFileName
	 * @throws IOException
	 */
	public CaptureFileSqueezeTime(String theFileName) throws IOException
	{
		super();
		myWr = new PCapFileWriter(theFileName);
		_isopen = true;
	}
	
	private long myStartTime = System.currentTimeMillis();
	
	@Override
	public boolean addPacket(byte[] thepkt, long time) throws IOException
	{
		if(_isopen)
		{
			throw new IOException("File is not open for writing");
		}
		myWr.addPacket(thepkt, myStartTime+myCounter);
		myCounter+=myInterval;
		return true;
	}
	
	@Override
	public void close() throws IOException
	{
		if(myWr != null && _isopen)
		{
			myWr.close();
			_isopen = false;
		}
		
	}
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		 CaptureIterator ir = new CaptureIterator(CaptureFileFactory.tryToCreateCaprtueFileReader("c:\\tmp\\concat.cap"));
		 CaptureFileSqueezeTime sq = new CaptureFileSqueezeTime("c:\\tmp\\concat_sq.cap");
		 
		 
		 while(ir.hasNext())
		 {
			 sq.addPacket(ir.next(), 0);
		 }
	}
}
