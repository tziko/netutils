package edu.huji.cs.netutils.files.enc;

import java.io.IOException;
import java.io.InputStream;

import edu.huji.cs.netutils.utils.ByteUtils;

/**
 * Enc capture file header.
 * This format uses different types of headers.
 * 
 * Only 3 of them are interesting, Version, EOF and FRAME. 
 * 
 * @author roni bar yanai
 *
 */
public class EncFilePacketHeader
{
	protected final static int REC_HDR_SIZE = 6;
	protected final static int SNIFFER_RECORD_VERSION_TYPE = 0x0100;
	protected final static int SNIFFER_RECORD_EOF_TYPE = 0x0300;
	protected final static int SNIFFER_RECORD_FRAME_TYPE = 0x0400;
	protected static final int ENC_FRAME_HEADER_SIZE = 14;
	
	// holds the type of the header and it length.
	private int myType = 0;
	private int myLength = 0;
	
	/**
	 * 
	 * @return true if header is a frame header.
	 */
	public boolean isFrame()
	{
		return isFrame;
	}

	private boolean isFrame = false;
	private boolean isEOF = false;
	
	/**
	 * 
	 * @return true if header is EOF header.
	 */
	public boolean isEOF()
	{
		return isEOF;
	}

	// internal frame header
	private EncFrameHdr myFrameHeader = null;
	
	
	/**
	 * build frame header from packet and timestamp.
	 * @param pkt
	 * @param time
	 * @return the header.
	 */
	protected static byte[] init(byte pkt[], long time)
	{
		int pos = 0;		
	    byte arr[] = new byte[REC_HDR_SIZE+ENC_FRAME_HEADER_SIZE];
	    
	    pos = 0;
	    ByteUtils.setBigIndianInBytesArray(arr, pos, SNIFFER_RECORD_FRAME_TYPE, 2);
	    pos+=2;
	    ByteUtils.setLittleIndianInBytesArray(arr, pos, pkt.length+ENC_FRAME_HEADER_SIZE, 2);
	    pos+=4;
	    ByteUtils.setLittleIndianInBytesArray(arr, pos, time, 2);
	    pos+=2;
	    ByteUtils.setLittleIndianInBytesArray(arr,pos,time >> 16,2);
	    pos+=2;
	    ByteUtils.setLittleIndianInBytesArray(arr,pos,time >> 32,1);
	    pos+=1;
	    ByteUtils.setLittleIndianInBytesArray(arr,pos,0,1);
	    pos+=1;
	    ByteUtils.setLittleIndianInBytesArray(arr,pos,pkt.length,2);
	    pos+=2;
	    ByteUtils.setLittleIndianInBytesArray(arr,pos,0,1);
	    pos+=1;
	    ByteUtils.setLittleIndianInBytesArray(arr,pos,0,1);
	    pos+=1;
	    ByteUtils.setLittleIndianInBytesArray(arr,pos,2,0);
	    pos+=2;
	    return arr;

	}
	
	/**
	 * init header.
	 * Will parse 3 types of header and will skip the rest.
	 * @param in - input stream.
	 * @throws IOException
	 */
	protected void init(InputStream in) throws IOException
	{
		byte arr[] = new byte[REC_HDR_SIZE];
		int n = in.read(arr);
		if( n == -1)
		{
			isEOF = true;
			return;
		}
		if (n != REC_HDR_SIZE)
			throw new IOException("corrupted file");
		
		int pos = 0;
		myType = ByteUtils.getByteNetOrderTo_unit16(arr, 0);
		pos+=2;
		myLength = ByteUtils.getByteLittleEndian_unit16(arr, pos);
		switch(myType)
		{
		case SNIFFER_RECORD_VERSION_TYPE:
		{
			isFrame = false;
			// we don't care about it at the moment, but we might
			// in the future. currently just skip it.
			in.skip(myLength);
			break;
		}
		case SNIFFER_RECORD_EOF_TYPE:
		{
			isEOF = true;
			break;
		}
		case SNIFFER_RECORD_FRAME_TYPE:
			isFrame = true;
			myFrameHeader = new EncFrameHdr();
		    arr = new byte[ENC_FRAME_HEADER_SIZE];
		    n = in.read(arr);
		    if (n != arr.length)
		    {
		    	throw new IOException("Unexpected end of file");
		    }
		    pos = 0;
		    myFrameHeader.myTimeLow = ByteUtils.getByteLittleEndian_unit16(arr, pos);
		    pos+=2;
		    myFrameHeader.myTimeMid=ByteUtils.getByteLittleEndian_unit16(arr, pos);
		    pos+=2;
		    myFrameHeader.myTimeHigh = ByteUtils.getByteNetOrderTo_uint8(arr, pos);
		    pos+=1;
		    myFrameHeader.myDay = ByteUtils.getByteNetOrderTo_uint8(arr, pos);
		    pos+=1;
		    myFrameHeader.mySize=ByteUtils.getByteLittleEndian_unit16(arr, pos);
		    pos+=2;
		    myFrameHeader.myFS = ByteUtils.getByteNetOrderTo_uint8(arr, pos);
		    pos+=1;
		    myFrameHeader.myFlags = ByteUtils.getByteNetOrderTo_uint8(arr, pos);
		    pos+=1;
		    myFrameHeader.myTrueSize=ByteUtils.getByteLittleEndian_unit16(arr, pos);
		    pos+=2;
		    break;
		   default:
			   isFrame = false;
			// we don't care about it at the moment, but we might
			// in the future. currently just skip it.
			in.skip(myLength);
			break;
			   
  
		}
	}
	
	/**
	 * if header is of frame type the return the length.
	 * @return
	 */
	public int getFrameSize()
	{
		if(isFrame)
		{
			return myFrameHeader.mySize;
		}
		return 0;
	}
	
	/**
	 * 
	 * @return time stamp
	 */
	public long getTime()
	{
		if(isFrame)
		{
			return myFrameHeader.getTime();
		}
		
		return 0;
	}

	// frame header format.
	class EncFrameHdr
	{
		long myTimeLow; // 2 bytes 
		long myTimeMid; // 2 bytes
		long myTimeHigh; // 1 byte
		int myDay; // 1 byte
		int mySize; //2 bytes
		int myFS; // 1 byte
		int myFlags; // 1 byte
		int myTrueSize ; // 2 bytes
		int myRsvd; // 2 bytes
		
		public long getTime()
		{
			long time = myTimeLow | (myTimeMid << 16) | ( myTimeHigh << 32);
			return time;
		}
		
	}
}
