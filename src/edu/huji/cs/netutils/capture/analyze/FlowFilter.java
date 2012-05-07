package edu.huji.cs.netutils.capture.analyze;

/**
 * Interface for generating flow predicates.
 * 
 * @author roni bar yanai
 */
public interface FlowFilter
{
	/**
	 * 
	 * @param flow
	 * @return true if flow in set and false otherwise 
	 */
	public boolean filter(Flow flow);
}
