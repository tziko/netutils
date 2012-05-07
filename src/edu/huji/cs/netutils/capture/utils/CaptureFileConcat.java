package edu.huji.cs.netutils.capture.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;

/**
 * Utility class for concatenating capture files.
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class CaptureFileConcat
{
	private ArrayList<String> myCapList = new ArrayList<String>();
	private HashMap<String, Integer> myCapIndex = new HashMap<String, Integer>();

	private String myTargetFileName = null;

	private PCapFileWriter myWr = null;
	
	private long myLastTimeStamp = 0;
	
	private long myTotalPkts = 0;

	/**
	 * Create new capture file
	 * @param theTargetFileName
	 * @throws IOException
	 */
	public CaptureFileConcat(String theTargetFileName) throws IOException
	{
		super();
		myTargetFileName = theTargetFileName;

		initWriter();
	}
	
	/**
	 * Concat to output stream
	 * @param theOutStream
	 * @throws IOException
	 */
	public CaptureFileConcat(OutputStream theOutStream) throws IOException
	{
		myWr = new PCapFileWriter(theOutStream);
		_isopen = true;
	}

	private boolean _isopen = false;

	private void initWriter() throws IOException
	{
		myWr = new PCapFileWriter(myTargetFileName);
		_isopen = true;
	}
	
	/**
	 * close file for writing.
	 * should be called last to make sure data is flushed.
	 * @throws IOException
	 */
	public void closeFile() throws IOException
	{
		if(_isopen)
		{
			myWr.close();
			_isopen = false;
		}
	}

	/**
	 * Add capture file.
	 * Will read all packets from file and add them to the curret
	 *  file while maintaining the relative timestamps.
	 * @param theFileName - file to add
	 * @throws NetUtilsException
	 * @throws IOException
	 */
	public void appendFile(String theFileName) throws NetUtilsException, IOException
	{
		if (!_isopen)
		{
			throw new NetUtilsException("File is closed for writing");
		}
		
		CaptureFileReader rd = CaptureFileFactory.tryToCreateCaprtueFileReader(theFileName);

		// keep info, where each capture file begins.
		myCapIndex.put(theFileName, (int) myTotalPkts);
		
		
		byte data[] = null;

		// mainting data stamps
		long timestamp = 0;
		long ltimestamp = 0;
		boolean isFirst = true;
		
		// add packets
		while ((data = rd.ReadNextPacket()) != null)
		{
			if(isFirst)
			{
				isFirst = false;
				timestamp = rd.getTimeStamp();
			}
			ltimestamp = rd.getTimeStamp()-timestamp+myLastTimeStamp;
			myWr.addPacket(data,ltimestamp);
			myTotalPkts++;
		}
		
		// remember last time stamp.
		myLastTimeStamp = ltimestamp;
		myCapList.add(theFileName);
	}

}
