package edu.huji.cs.netutils.files.xcp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.pcap.PCapFileHeader;

/**
 * Reader for XNP capture type.
 * 
 * 
 * @author roni bar yanai
 *
 */
public class XNPFileReader implements CaptureFileReader
{


	private static final long XNP_HEADER_LENGTH = 128;

	private static final int XCP_BLOCK_HDR_LEN = 40;

	private String myFileName = null;

	private InputStream myInStrm = null;

	private PCapFileHeader myPcapFileHeader = null;
	
	private long myPktCnt = 0;

	/**
	 * open cap file
	 * @param theFileName
	 * @throws IOException
	 */
	public XNPFileReader(String theFileName) throws IOException
	{
		myFileName = theFileName;
		initStream(theFileName);
	} 
	
	private boolean _isValidFile = false;
	
	private void initStream(String theFileName) throws IOException
	{
		myInStrm = new FileInputStream(new File(theFileName));
		byte tmp[] = new byte[(int) XNP_HEADER_LENGTH];
		myInStrm.read(tmp);
		if(new String(tmp).startsWith("XCP"))
		{
			_isValidFile = true;
		}
	}
	
	byte _lastHdr[] = null;
	
	@Override
	public byte[] ReadNextPacket() throws IOException
	{
		byte hdr[] = new byte[XCP_BLOCK_HDR_LEN];
		int n = myInStrm.read(hdr);
		if( n != XCP_BLOCK_HDR_LEN)
			return null;
	
		_lastHdr = hdr;
		int length = hdr[9] & 0xff;
		length = length << 8;
		length+= (hdr[8] & 0xff);
		
		byte toRet[] = new byte[length];
		n = myInStrm.read(toRet);
		if (n != length)
		{
			throw new IOException("File is corrupt");
		}
		return toRet;
	}
	
	/**
	 * 
	 */
	public long getTimeStamp()
	{
		return 0;
	}
 
	/**
	 * 
	 * @return
	 */
	public boolean isValidEncFile()
	{
		return _isValidFile;
	}


	@Override
	public long getCurrentPacket()
	{
		return myPktCnt;
	}

}
