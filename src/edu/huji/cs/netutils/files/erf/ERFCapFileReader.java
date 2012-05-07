package edu.huji.cs.netutils.files.erf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.huji.cs.netutils.files.CaptureFileReader;

public class ERFCapFileReader implements CaptureFileReader
{

	private long myPktCnt = 0;
	
	private FileInputStream myInStream = null;
	

	
	private String myFileName = null;
	
	private long myBytes = 0;
	
	public ERFCapFileReader(String theFileName) throws FileNotFoundException
	{
		myFileName = theFileName;
		initStream();
	}
	
	private void initStream() throws FileNotFoundException
	{
		myInStream = new FileInputStream(new File(myFileName));
	}
	
	private ERFPacketHeader myLastHdr = new ERFPacketHeader();

	@Override
	public byte[] ReadNextPacket() throws IOException
	{
		myLastHdr = myLastHdr.readNextHeader(myInStream);
		if (myLastHdr == null)
		{
			return null;
		}

		myBytes+=ERFPacketHeader.ERF_HEADER_LENGTH;
		
		byte data[] = new byte[myLastHdr.myWlen];
		if (data.length == 0 ||  myInStream.read(data,0,data.length) != data.length)
		{
			// file is corrupted.
			return null;
		}
		


		long skip = myLastHdr.myRlen - myLastHdr.myWlen - ERFPacketHeader.ERF_HEADER_LENGTH;
		if (myInStream.skip(skip) != skip)
		{
			throw new IOException("File is corrupted!");
		}

		myBytes+=myLastHdr.myWlen;
		myBytes+=skip;
		
		myPktCnt++;
		return data;
	}

	@Override
	public long getTimeStamp()
	{
		if (myLastHdr != null)
		{
			return myLastHdr.myTimeValMSec + myLastHdr.myTimeValSec*1000;
		}
		return 0;
	}
	
	public ERFPacketHeader getLastPktHdr()
	{
		return myLastHdr;
	}

	@Override
	public long getCurrentPacket()
	{
		return myPktCnt;
	}

	public static void main(String[] args) throws IOException
	{
		ERFCapFileReader rd = new ERFCapFileReader("c:\\tmp\\pacp_format2.erf");
		byte data[] = null;
		int i = 0;
		while((data = rd.ReadNextPacket()) != null)
		{
			System.out.println("another packet:"+rd.getCurrentPacket());
			System.out.println(rd.myLastHdr.toString());
			if (i ==5)
			{
				break;
			}
			i++;
		}
		
		
	}

	public long getBytes()
	{
		return myBytes;
	}
}
