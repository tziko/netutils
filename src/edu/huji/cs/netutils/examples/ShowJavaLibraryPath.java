package edu.huji.cs.netutils.examples;

/**
 * The program prints JVM in use default java.library.path
 * 
 * @author roni bar-yanai
 *
 */
public class ShowJavaLibraryPath
{
	public static void main(String[] args)
	{
		System.out.println(System.getProperty("java.library.path"));
	}
}
