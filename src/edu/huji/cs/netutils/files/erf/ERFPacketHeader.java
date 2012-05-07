package edu.huji.cs.netutils.files.erf;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import edu.huji.cs.netutils.utils.ByteUtils;

/**
 * 
 * 
 * // the C code. 
 * /typedef struct erf_record { 
 *  erf_timestamp_t ts; 
 *  guint8 type;
 *  guint8 flags; 
 *  guint16 rlen; 
 *  guint16 lctr; 
 *  guint16 wlen;
 *  } erf_header_t;
 * 
 * @author roni bar yanai
 * 
 */
public class ERFPacketHeader
{

	public static final int ERF_HEADER_LENGTH = 18;
	protected static final int ETH_TYPE = 2;

	// two unit32_t
	protected long myTimeValSec = 0;
	protected long myTimeValMSec = 0;

	// two unit8_t
	protected int myPktType = ETH_TYPE;
	protected int myFlags = 0;

	// uint16_t
	protected int myRlen = 0;
	private int myLctr = 0;
	protected int myWlen = 0;

	private int myPktPad = 0;

	public ERFPacketHeader readNextHeader(FileInputStream in) throws IOException
	{
		byte data[] = new byte[ERF_HEADER_LENGTH];
		if (in.read(data, 0, ERF_HEADER_LENGTH) != data.length)
		{
			return null;
		}

		myTimeValSec = ByteUtils.getByteNetOrderTo_unit32(data, 0);
		myTimeValMSec = ByteUtils.getByteNetOrderTo_unit32(data, 4);

		myPktType = ByteUtils.getByteNetOrderTo_uint8(data, 8);
		myFlags = ByteUtils.getByteNetOrderTo_uint8(data, 9);

		myRlen = ByteUtils.getByteNetOrderTo_unit16(data, 10);
		myLctr = ByteUtils.getByteNetOrderTo_unit16(data, 12);
		myWlen = ByteUtils.getByteNetOrderTo_unit16(data, 14);

		myPktPad = ByteUtils.getByteNetOrderTo_unit16(data, 16);

		return this;
	}
	
	public void writeHeader(OutputStream out) throws IOException
	{
		byte data[] = new byte[ERF_HEADER_LENGTH];
		ByteUtils.setBigIndianInBytesArray(data, 0, myTimeValSec, 4);
		ByteUtils.setBigIndianInBytesArray(data, 4, myTimeValMSec, 4);
		
		
		
		ByteUtils.setBigIndianInBytesArray(data, 8, myPktType, 1);
		ByteUtils.setBigIndianInBytesArray(data, 9, myFlags, 1);
		ByteUtils.setBigIndianInBytesArray(data, 10, myRlen, 2);
		ByteUtils.setBigIndianInBytesArray(data, 12, myLctr, 2);
		ByteUtils.setBigIndianInBytesArray(data, 14, myWlen, 2);
		ByteUtils.setBigIndianInBytesArray(data, 16, myPktPad, 2);
		out.write(data);
	}
	
	public void setPacketLength(int length)
	{
		
		myWlen = length;
		myRlen = myWlen + ERFPacketHeader.ERF_HEADER_LENGTH; 
	}

	@Override
	public String toString()
	{
		StringBuffer sb = new StringBuffer();
		// two unit32_t
		sb.append("Sec Val  :"+ myTimeValSec);
		sb.append("\n");
		sb.append("\nMSec Val :"+myTimeValMSec);

		// two unit8_t
		sb.append("\nPkt Type :"+myPktType);
		sb.append("\nFlags    :"+myFlags);

		// uint16_t
		sb.append("\nRLen     :"+myRlen);
		sb.append("\nLctr     :"+myLctr); 
		sb.append("\nWLen     :"+myWlen);

		sb.append("\nPkt Pad  :"+myPktPad);
		sb.append("\n");
		return sb.toString();
	}

}
