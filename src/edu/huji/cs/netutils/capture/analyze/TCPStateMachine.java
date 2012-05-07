package edu.huji.cs.netutils.capture.analyze;

import edu.huji.cs.netutils.parse.FiveTuple;
import edu.huji.cs.netutils.parse.TCPPacket;

/**
 * Check TCP flow start and end states.
 * In many practical cases we want to examine only flows which has a complete
 *  3-way-handshake or other specific flow establishment or/and ending property.
 *  
 * The class purpose is two follow the flow establishment and disconnection. 
 * 
 * 
 * @author roni bar-yanai
 *
 */
public class TCPStateMachine
{
	enum EstablishStates {
		NONE,
		SYN,
		SYN_ACK,
		ACK,
		ESTABLISHED
	}
	
	enum EndStates {
		NONE,
		FIN_I,
		ACK_R,
		FIN_R,
		ACK_I,
		FIN2_I,
		ACK2_R,
		FIN2_R,
		ACK2_I,
		ENEDED,
		RST
	}
	
	private FiveTuple myFiveTuple = null;
	
	private boolean isMultipleSyn = false;
	
	public TCPStateMachine(FiveTuple ft)
	{
		myFiveTuple = ft;
	}
	
	// 
	private EstablishStates myState = EstablishStates.NONE;
	
	private EndStates myEndState = EndStates.NONE;
	
	public boolean isMultipleSyn()
	{
		return isMultipleSyn;
	}
	
	private void checkEnd(TCPPacket tcppkt, boolean isInitiator)
	{
		boolean ack = tcppkt.isAck();
		boolean rst = tcppkt.isRst();
		boolean fin = tcppkt.isFin();
		
		
	}
	
    public void handlePacket(TCPPacket tcppkt)
    {	
    	
    	if(myState == EstablishStates.ESTABLISHED)
    		return;
    	
    	boolean ack = tcppkt.isAck();
    	boolean syn = tcppkt.isSyn();
    	boolean isInitiator = tcppkt.getUnderlyingIPPacketBase().getSourceIP().equals(myFiveTuple.getMySrcIp());
    	
    	switch(myState)
    	{
    	case NONE:
    		if (syn && !ack && isInitiator)
    		{
    			myState = EstablishStates.SYN;
    		}
    		return;
    	case SYN:
    		if (syn && ack && !isInitiator)
    		{
    			myState = EstablishStates.SYN_ACK;
    		} else if (syn && !ack && isInitiator)
    		{
    			isMultipleSyn = true;
    			myState = EstablishStates.SYN;
    		}
    		return;
    	case SYN_ACK:
    		if (ack && isInitiator) {
    			myState = EstablishStates.ESTABLISHED;
    		}
    		return;
    	default:
    		myState = EstablishStates.NONE;
    	}
    	
    }
    
    public boolean isEstablished()
    {
    	return myState == EstablishStates.ESTABLISHED;
    }
}
