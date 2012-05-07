package edu.huji.cs.netutils.examples.ping;

import edu.huji.cs.netutils.utils.ByteUtils;

/**
 * put the parameters to byte array.<br>
 * get parameters from byte array.<br>
 * 
 * @author roni bar yanai
 */
class PingData
{
	// we skip the set/get methods here for simplicity and give 
	// direct access.
	public long time = 0;

	public int sequence = 0;

	public int id = 0;

	public PingData()
	{
	}

	public PingData(byte[] theData)
	{
		id = ByteUtils.getByteNetOrderTo_unit16(theData, 0);
		sequence = ByteUtils.getByteNetOrderTo_unit16(theData, 2);
		time = ByteUtils.getByteNetOrder(theData, 4, 8);
	}
	
	public byte[] getTimeAsByteArray()
	{
		byte toRet[] = new byte[4];
		ByteUtils.setBigIndianInBytesArray(toRet, 0, time,4);
		return toRet;
	}
	
	public void setTimeFromArray(byte data[])
	{
		time = ByteUtils.getByteNetOrder(data, 0, 4);
	}

	public byte[] getAsByteArray()
	{
		byte[] tmp = new byte[12];
		ByteUtils.setBigIndianInBytesArray(tmp, 0, id, 2);
		ByteUtils.setBigIndianInBytesArray(tmp, 2, sequence, 2);
		ByteUtils.setBigIndianInBytesArray(tmp, 4, time, 8);
		return tmp;
	}

}