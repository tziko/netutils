package edu.huji.cs.netutils.files.enc;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureFileValid;
import edu.huji.cs.netutils.files.CaptureIterator;
/**
 * Enc capture file reader
 * 
 * 
 * @author roni bar yanai
 *
 */
public class EncFileReader  implements CaptureFileReader,CaptureFileValid
{

	private static final long ENC_HEADER_LENGTH = 17;

	private String myFileName = null;

	private InputStream myInStrm = null;
	
	private long myPktCnt = 0;

	/**
	 * open cap file
	 * @param theFileName
	 * @throws IOException
	 */
	public EncFileReader(String theFileName) throws IOException
	{
		myFileName = theFileName;
		initStream(theFileName);
	} 
	
	private boolean _isValidFile = false;
	
	/**
	 * read header and validate that the type match.
	 * @param theFileName
	 * @throws IOException
	 */
	private void initStream(String theFileName) throws IOException
	{
		myInStrm = new FileInputStream(new File(theFileName));
		byte tmp[] = new byte[(int) ENC_HEADER_LENGTH];
		myInStrm.read(tmp);
		if(new String(tmp).startsWith("TRSNIFF"))
		{
			_isValidFile = true;
		}
	}

	
	// caching last header for getting information from it.
	private EncFilePacketHeader _lastHdr = null;
	@Override
	public byte[] ReadNextPacket() throws IOException
	{
		boolean found = false;

		// in the format we might have additional headers, so
		// we skip the headers until we get into frame header or eof
		// header
		_lastHdr = new EncFilePacketHeader();
		_lastHdr.init(myInStrm);
		while(!found && !_lastHdr.isEOF())
		{
			if(_lastHdr.isFrame())
			{
				int size = _lastHdr.getFrameSize();
				byte buff[] = new byte[size];
				myInStrm.read(buff);
				myPktCnt++;
				return buff;
			}
			_lastHdr.init(myInStrm);
		}
		return null;
		
	}
	
	/**
	 * @return last read packet time stamp or zero if no such.
	 */
	public long getTimeStamp()
	{
		if(_lastHdr != null)
		{
			return _lastHdr.getTime();
		}
		
		return 0;
	}
 
	/**
	 * 
	 * @return true if the file is of the expected format.
	 */
	public boolean isValid()
	{
		return _isValidFile;
	}


	@Override
	public long getCurrentPacket()
	{
		return myPktCnt;
	}


	/**
	 * 
	 * @return the file name.
	 */
	public String getMyFileName()
	{
		return myFileName;
	}

}
