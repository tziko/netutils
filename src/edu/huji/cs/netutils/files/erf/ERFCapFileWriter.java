package edu.huji.cs.netutils.files.erf;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.files.CaptureFileFactory;
import edu.huji.cs.netutils.files.CaptureFileReader;
import edu.huji.cs.netutils.files.CaptureFileWriter;

public class ERFCapFileWriter implements CaptureFileWriter
{

	// the out stream
	private FileOutputStream myOutStrm = null;
	
	private String myFileName = null;
	
	private long   myPktCntr = 0;
	
	/**
	 * open new file
	 * @param file
	 * @throws IOException - on file creation failure.
	 */
	public ERFCapFileWriter(File theFile) throws IOException
	{
		myFileName = theFile.getName();
		initStream(theFile);
	}
	
	private boolean _isopen = false;
	
	private void initStream(File theFile) throws FileNotFoundException
	{
		// just open stream, no file header like in 
		// other formats.
		myOutStrm = new FileOutputStream(theFile);
		_isopen = true;
	}

	/**
	 * open new file
	 * @param file - the file name
	 * @throws IOException - on file creation failure.
	 */
	public ERFCapFileWriter(String file) throws IOException
	{
		this(new File(file));
		
	}
	
	
	@Override
	public boolean addPacket(byte[] thepkt, long theTime) throws IOException
	{
		if(!_isopen)
		  return false;
		
		
		System.out.println("time:"+theTime);
		
		ERFPacketHeader hdr = new ERFPacketHeader();
		hdr.myTimeValMSec = (theTime & 0xffffffffl);
		hdr.myTimeValSec = theTime / 1000;
	
		
		hdr.myWlen = thepkt.length;
		hdr.myRlen = hdr.myWlen + ERFPacketHeader.ERF_HEADER_LENGTH;
						
		hdr.writeHeader(myOutStrm);
		myOutStrm.write(thepkt);
		
		myPktCntr++;
		return true;
	}

	@Override
	public void close() throws IOException
	{
		if (_isopen)
		{
			myOutStrm.flush();
			myOutStrm.close();
			_isopen = false;
			myOutStrm = null;
		}
		
	}
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		CaptureFileReader rd = CaptureFileFactory.createCaptureFileReader("c:\\tmp\\ftp.cap");
		//ERFCapFileReader rd = new ERFCapFileReader("c:\\tmp\\pacp_format2.erf");
		
		ERFCapFileWriter wr = new ERFCapFileWriter("c:\\tmp\\con_ftp4.erf");
		
		byte data[] = null;
		int i =0;
		System.out.println("--------------------------------");
		while((data = rd.ReadNextPacket()) != null)
		{
			System.out.println("-----------("+i+")---------------------");
			wr.addPacket(data, rd.getTimeStamp());
			/*if (i ==5)
				break;*/
			i++;
		}
		
		wr.close();
	}

}
