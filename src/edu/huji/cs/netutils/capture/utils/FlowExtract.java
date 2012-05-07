package edu.huji.cs.netutils.capture.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.analyze.CaptureFileFlowAnalyzer;
import edu.huji.cs.netutils.capture.analyze.Flow;
import edu.huji.cs.netutils.files.CaptureFileWriter;
import edu.huji.cs.netutils.files.pcap.PCapFileWriter;

/**
 * Utility for extracting flows from a capture file.
 *  
 *  Flows are identified by their number (starting with one) in the capture file, by a packet number or 
 *   by their five tuple.
 *   
 *  For performance we first load a capture file and then call extract for flows, this 
 *   way we can extract many flows with a single capture file analyze.
 * 
 * @author roni bar-yanai
 *
 */
public class FlowExtract
{
	private CaptureFileFlowAnalyzer myCA = null;
	
	private boolean _isBatchMode = false;
	
	private CaptureFileWriter myWr = null;
	
	private int myLimit = 0;
	
	public FlowExtract()
	{}
	
	private boolean _isloaded = false;
	
	/**
	 * load capture into memory.
	 * @param theFilename
	 * @throws IOException
	 * @throws NetUtilsException
	 */
	public void loadCapture(String theFilename) throws IOException, NetUtilsException
	{
		myCA = new CaptureFileFlowAnalyzer(theFilename);
		_isloaded = true;
	}
	
	/**
	 * load capture file
	 * @param theFileName - file name
	 * @throws IOException
	 * @throws NetUtilsException
	 */
	public void loadCapturFile(String theFileName) throws IOException, NetUtilsException
	{
		loadCaptureFileFlowAnalyzer(new CaptureFileFlowAnalyzer(theFileName));
	}
	
	/**
	 * load capture analyzer file into memory.
	 * useful when we already have {@link CaptureFileFlowAnalyzer} in hand.  
	 * @param theCA
	 */
	public void loadCaptureFileFlowAnalyzer(CaptureFileFlowAnalyzer theCA)
	{
		if(theCA != null)
		{
			myCA = theCA;
			_isloaded = true;
		}
	}
	
	/**
	 * 
	 * @return total number of flows in capture file
	 *  (will return 0 if no file were loaded)
	 */
	public long getTotalNumOfFlows()
	{
		if(_isloaded)
		{
			return myCA.getNumberOfFlows();
		}
		
		return 0;
	}
	
	/**
	 * Set the limit of packets per flow.
	 * This extraction will stop on packet n for each flow.
	 * @param n
	 */
	public void setLimit(int n)
	{
		if(n>0)
			myLimit = n;
	}
	
	/**
	 * Extract flow by idx and print it to std out 
	 *  as a readable text.
	 * @param idx
	 * @param payload - if true then will skip none payload packets and will 
	 *  print payload without the hex representation.
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowToScreen(int idx, boolean payload)
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return;
		}
		
		readableStringToScreen(myCA.getFlow(idx),System.out,payload);
	}
	
	/**
	 * Extract flow by idx and print it to std out 
	 *  as a readable text.
	 * @param idx
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowToScreen(int idx)
	{
		extractFlowToScreen(idx,false);
	}
	
	/**
	 * Extract flow by idx and print it to std out 
	 *  as a readable text.
	 * @param idx
	 * @param payload - if true then will skip none payload packets and will 
	 *  print payload without the hex representation.
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowToOutputStream(int idx, OutputStream theOutStream, boolean payload)
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return;
		}
		
		readableStringToScreen(myCA.getFlow(idx),theOutStream,payload);
	}
	
	/**
	 * Extract flow by idx and print it to std out 
	 *  as a readable text.
	 * @param idx
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowToOutputStream(int idx, OutputStream theOutStream)
	{
		extractFlowToOutputStream(idx, theOutStream, false);
	}
	
	/**
	 * start batch mode.
	 * In batch mode all flows are written to the supplied
	 * {@link CaptureFileWriter}
	 * @param wr
	 * @return ture on success
	 */
	public boolean setBathMode(CaptureFileWriter wr)
	{
		if (wr == null)
			throw new NullPointerException();
		
		if(!_isBatchMode )
		{
			_isBatchMode = true;
			myWr = wr;
			return true;
		}
		return false;
	}
	
	/**
	 * close batch mode.
	 */
	public void clsoeBatchMode()
	{
		if(_isBatchMode)
		{
			try
			{
				myWr.close();
			} catch (IOException e)
			{
				e.printStackTrace();
			}
			_isBatchMode = false;
		}
	}
	
	/**
	 * extract flow by packet number, that is the flow which this packet
	 *  is part of and print it to std out is readable text.
	 * @param idx - packet index starting with one
	 * @param payload - if true then will skip none payload packets and will 
	 *  print payload without the hex representation.
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowOfPacketToScreen(int idx,boolean payload)
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return;
		}
		
		readableStringToScreen(myCA.getFlowOfPkt(idx),System.out,payload);
		
	}
	
	/**
	 * extract flow by packet number, that is the flow which this packet
	 *  is part of and print it to std out is readable text.
	 * @param idx - packet index starting with one
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowOfPacketToScreen(int idx)
	{
		extractFlowOfPacketToScreen(idx,false);
		
	}
	
	/**
	 * extract flow by packet number, that is the flow which this packet
	 *  is part of and print it to output stream   is readable text.
	 * @param idx - packet index starting with one
	 * @param theOutputStream
	 * @param payloadonly - if true then will skip none payload packets and will 
	 *  print payload without the hex representation.
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowOfPacketToOutputStream(int idx,OutputStream theOutputStream, boolean payloadonly)
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return;
		}
		
		readableStringToScreen(myCA.getFlowOfPkt(idx),theOutputStream,payloadonly);
		
	}
	

	/**
	 * extract flow by packet number, that is the flow which this packet
	 *  is part of and print it to output stream   is readable text.
	 * @param idx - packet index starting with one
	 * @param theOutputStream
	 * @exception IndexOutOfBoundsException - if index in not in range
	 */
	public void extractFlowOfPacketToOutputStream(int idx,OutputStream theOutputStream)
	{
		extractFlowOfPacketToOutputStream(idx, theOutputStream,false);
	}
	
	/**
	 *  extract flow by packet number, that is the flow which this packet
	 *  is part of. write the flow to batched capture file.
	 * @param idx
	 * @return true on success
	 * @throws IOException
	 */
	public boolean extractFlowOfPktToCapBatch(int idx) throws IOException
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return false;
		}
		
		if(!_isBatchMode)
			throw new IOException("No batch open were called");
		
		return writeFlowToCap(myWr,myCA.getFlowOfPkt(idx));
	}
	
	/**
	 *  extract flow by packet number, that is the flow which this packet
	 *  is part of. write the flow to capture file.
	 * @param idx
	 * @param theFileName - the target file name
	 * @return true on success
	 * @throws IOException
	 */
	public boolean extractFlowOfPktToCap(int idx, String theFileName) throws IOException
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return false;
		}
		
		return writeFlowToCap(theFileName,myCA.getFlowOfPkt(idx));
	}
	
	/**
	 * extract flow by flow number. write the flow to new capture file.
	 * @param idx
	 * @param theFileName - target file
	 * @return true on success
	 * @throws IOException
	 */
	public boolean extractFlowToCap(int idx, String theFileName) throws IOException
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return false;
		}
				
		return writeFlowToCap(theFileName,myCA.getFlow(idx));
	}
	
	/**
	 * extract flow by flow number. write the flow to new capture file.
	 * @param idx
	 * @param theFileName - target file
	 * @return true on success
	 * @throws IOException
	 */
	public boolean extractFlowToCapBatch(int idx) throws IOException
	{
		if (!_isloaded)
		{
			System.out.println("no capture file was loaded");
			return false;
		}
		
		if(!_isBatchMode)
			throw new IOException("noo in batch mode");
				
		return writeFlowToCap(myWr,myCA.getFlow(idx));
	}
	
	
	/**
	 * 
	 * @param theFileName
	 * @param flow
	 * @return
	 * @throws IOException
	 */
	private boolean writeFlowToCap(String theFileName,Flow flow) throws IOException
	{
		PCapFileWriter wr = new PCapFileWriter(theFileName);
		
		flow.writeToCaptureFile(wr);
		
		wr.close();

		return true;
	}
	
	/**
	 * 
	 * @param theFileName
	 * @param flow
	 * @return
	 * @throws IOException
	 */
	private boolean writeFlowToCap(CaptureFileWriter wr,Flow flow) throws IOException
	{
			
		flow.writeToCaptureFile(wr,myLimit);
		
		wr.close();

		return true;
	}
	
	/**
	 * print flow to stdout.
	 * @param flow
	 */
	private void readableStringToScreen(Flow flow,OutputStream theOutStream,boolean payloadonly)
	{
		PrintStream out = new PrintStream(theOutStream);
		StringBuffer sb = new StringBuffer();
		if(payloadonly)
		{
			flow.payloadToReadbleText(sb,myLimit);
		}
		else
		{
			flow.toReadableText(sb,myLimit);
		}
		out.print(sb.toString());
			
    }
	
	public static void main(String[] args) throws IOException, NetUtilsException
	{
		FlowExtract fe = new FlowExtract();
		fe.loadCapture("c:\\tmp\\ftp.cap");
		
		fe.extractFlowToCap(1, "c:\\tmp\\ex_test.cap");
	}
	
}
