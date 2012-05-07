package edu.huji.cs.netutils.files.enc;

import java.io.FileOutputStream;
import java.io.IOException;

import javax.print.attribute.standard.Finishings;

import edu.huji.cs.netutils.files.CaptureFileWriter;

/**
 * Enc capture file writer.
 * 
 * 
 * @author roni bar yanai
 *
 */
public class EncFileWriter implements CaptureFileWriter
{

	// constant file header
	private static final byte ENC_HEADER[] = new byte[]{0x54,0x52,0x53,(byte)0x4e,
		                                                0x49,0x46,0x46,0x20,
		                                                0x64,0x61,0x74,0x61,
		                                                0x20,0x20,0x20,0x20,
		                                                (byte)0x1A}; 
	// constant version header.
	private static final byte VER_HEADER[] = new byte[]{0x01,00,0x12,00,00,00,
		0x4,0,0,0,0,0,
		(byte)0x4a,(byte)0x2e,0x4,0x1,0x1,
		0x1,0,0,0,
		0,0,0};//,0x4,0};
		
	
    // constant eof header 
	private static final byte EOF_HEADER[] = new byte[]{03,0,0,0,0,0};
	
	
	private FileOutputStream myOutstrm = null;
	
	boolean _isActive = false;
	
	/**
	 * create new enc capture file
	 * @param fileName
	 * @throws IOException
	 */
	public EncFileWriter(String fileName) throws IOException
	{
		myOutstrm = new FileOutputStream(fileName);
		
		// write the constant headers.
		myOutstrm.write(ENC_HEADER);
		myOutstrm.write(VER_HEADER);
		_isActive = true;
	}
	
	@Override
	public boolean addPacket(byte[] thepkt, long time) throws IOException
	{
		if(!_isActive)
		{
			throw new IOException("File was closed or not opended properly");
		}
		
		// create header for the packet.
        byte hdr[] =  EncFilePacketHeader.init(thepkt, time);
        
        // write the header and then the packet.
        myOutstrm.write(hdr);
        myOutstrm.write(thepkt);
		return true;
	}
	
	/**
	 * close the file.
	 * @throws IOException
	 */
	public void close() throws IOException
	{
		if(!_isActive)
			return;
		
		myOutstrm.write(EOF_HEADER);
		myOutstrm.close();
		_isActive = false;
		
	}
	
	
}
