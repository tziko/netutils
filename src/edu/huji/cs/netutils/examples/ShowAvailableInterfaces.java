package edu.huji.cs.netutils.examples;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.capture.JPCapInterface;

/**
 * The program prints all available interfaces to the standard output.
 *  
 * @author roni bar-yanai
 *
 */
public class ShowAvailableInterfaces
{
	public static void main(String[] args) throws NetUtilsException
	{
		JPCapInterface intArr[] = JPCap.getAllIntefacesNames();
		for(JPCapInterface next : intArr)
		{
			System.out.println(next.toString());
		}
	}
}
