package edu.huji.cs.netutils.inject.impl;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.inject.IPInjector;

/**
 * For internal use.
 * Interface to the c code.
 * Users should use JInject.
 * 
 * @see IPInjector
 * @author roni bar-yanai
 *
 */
public class JLibNetWraper
{
	
	/**
	 * constant for open libnet to run in link layer.
	 */
	private static final int LINK_LAYER_TYPE = 1;

	/**
	 * constant for open libnet in ip level
	 */
	private static final int RAW_IP_TYPE = 2;

	/**
	 * each instance has a unique id, an integer key where -1 stands for no key.
	 */
	private static final int NO_KEY = -1;

	/**
	 * single tone.
	 * all api is in c.
	 */
	private static JLibNetWraper INSTANCE = null;

	/**
	 * Access method.
	 * @return the wraper instance
	 * @throws NetUtilsException - will throw exception if cannot link (didn't find dll or so)
	 */
	public synchronized static JLibNetWraper getInsance() throws NetUtilsException
	{
		try
		{
			if (INSTANCE == null)
			{
				System.loadLibrary("netutils");
				INSTANCE = new JLibNetWraper();
			}
		}
		catch (UnsatisfiedLinkError e)
		{
			throw new NetUtilsException(e);
		}

		return INSTANCE;
	}

	/**
	 * private, can not be called by users. 
	 */
	private JLibNetWraper()
	{
	}

	/**
	 * Initialize a new instance of libnet.
	 * @param theDevice - name of the device (as shown by pcap).
	 * @return A JinjectKey which unqiely identifies this instance. 
	 *   will throw exception on failure.
	 * @throws NetUtilsException
	 */
	public JInjectKey libnetInitLinkLayer(String theDevice) throws NetUtilsException
	{
		// call c code to initialize new libnet instance.
		int result = libnet_init(LINK_LAYER_TYPE, theDevice);

		// if failed throw exception.
		if (result == NO_KEY)
		{
			throw new NetUtilsException();
		}
		else
		{
			return new JInjectKey(result);
		}
	}

	/**
	 * init libnet in raw ip mode.
	 * (no need to take care of mac,arps ...etc)
	 * @param theDevice
	 * @return A JinjectKey which uniquely identifies this instance. 
	 *   will throw exception on failure.
	 * @throws NetUtilsException
	 */
	public JInjectKey libnetInitRawIp(String theDevice) throws NetUtilsException
	{
		// open as raw ip (can send any ip packet)
		int result = libnet_init(RAW_IP_TYPE, theDevice);

		if (result == NO_KEY)
		{
			throw new NetUtilsException();
		}
		else
		{
			return new JInjectKey(result);
		}
	}

	/**
	 * call c code to initialize libnet instance
	 * @param injection_type
	 * @param device - the device name ( "eth1","eth0"..etc for linux)
	 * @return the key for the instance or NO_KEY for failure
	 */
	private native int libnet_init(int injection_type, String device);

	public native String get_last_error();

	/**
	 * Builds an Ethernet header. The RFC 894 Ethernet II header is almost 
	 * identical to the IEEE 802.3 header, with the exception that the field 
	 * immediately following the source address holds the layer 3 protocol (as
	 * opposed to frame's length). You should only use this function when 
	 * libnet is initialized with the LIBNET_LINK interface. 
	 * @param dst destination ethernet address
	 * @param src source ethernet address
	 * @param type upper layer protocol type
	 * @param payload optional payload or NULL
	 * @param payload_s payload length or 0
	 * @param l pointer to a libnet context
	 * @param ptag protocol tag to modify an existing header, 0 to build a new one
	 * @return protocol tag value on success, -1 on error
	 
	 libnet_ptag_t
	 libnet_build_ethernet(u_int8_t *dst, u_int8_t *src, u_int16_t type, 
	 u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag);
	 */

	public native boolean libnet_build_ethernet(byte[] dst, byte[] src, int type, byte[] payload, int key);

	/**
	 * Builds an Address Resolution Protocol (ARP) header.  Depending on the op 
	 * value, the function builds one of several different types of RFC 826 or
	 * RFC 903 RARP packets.
	 * @param hrd hardware address format
	 * @param pro protocol address format
	 * @param hln hardware address length
	 * @param pln protocol address length
	 * @param op ARP operation type
	 * @param sha sender's hardware address
	 * @param spa sender's protocol address
	 * @param tha target hardware address
	 * @param tpa targer protocol address
	 * @param payload optional payload or NULL
	 * @param payload_s payload length or 0
	 * @param l pointer to a libnet context
	 * @param ptag protocol tag to modify an existing header, 0 to build a new one
	 * @return protocol tag value on success, -1 on error

	 libnet_ptag_t
	 libnet_build_arp(u_int16_t hrd, u_int16_t pro, u_int8_t hln, u_int8_t pln,
	 u_int16_t op, u_int8_t *sha, u_int8_t *spa, u_int8_t *tha, u_int8_t *tpa,
	 u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag);
	 */

	public native boolean libnet_build_arp(int hrd, int pro, short hln, short pln, int op, byte[] sha, byte[] spa, byte[] tha, byte[] tpa, byte[] payload, int key);

	/**
	 * Builds an RFC 793 Transmission Control Protocol (TCP) header.
	 * @param sp source port
	 * @param dp destination port
	 * @param seq sequence number
	 * @param ack acknowledgement number
	 * @param control control flags
	 * @param win window size
	 * @param sum checksum (0 for libnet to autofill)
	 * @param urg urgent pointer
	 * @parama len total length of the TCP packet (for checksum calculation)
	 * @param payload_s payload length or 0
	 * @param l pointer to a libnet context
	 * @param ptag protocol tag to modify an existing header, 0 to build a new one
	 * @return protocol tag value on success, -1 on error
	 
	 libnet_ptag_t
	 libnet_build_tcp(u_int16_t sp, u_int16_t dp, u_int32_t seq, u_int32_t ack,
	 u_int8_t control, u_int16_t win, u_int16_t sum, u_int16_t urg, u_int16_t len, 
	 u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag);
	 */

	public native boolean libnet_build_tcp(long sp, long dp, long seq, long ack, short control, long win, long sum, long urg, long len, byte[] payload, int key);

	/**
	 * Builds an RFC 768 User Datagram Protocol (UDP) header.
	 * @param sp source port
	 * @param dp destination port
	 * @param len total length of the UDP packet
	 * @param sum checksum (0 for libnet to autofill)
	 * @param payload optional payload or NULL
	 * @param payload_s payload length or 0
	 * @param l pointer to a libnet context
	 * @param ptag protocol tag to modify an existing header, 0 to build a new one
	 * @return protocol tag value on success, -1 on error
	 
	 libnet_ptag_t
	 libnet_build_udp(u_int16_t sp, u_int16_t dp, u_int16_t len, u_int16_t sum,
	 u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag);
	 */

	public native boolean libnet_build_udp(int sp, int dp, int len, int sum, byte[] payload, int key);

	/**
	 * Builds a version 4 RFC 791 Internet Protocol (IP) header.
	 * @param len total length of the IP packet including all subsequent data
	 * @param tos type of service bits
	 * @param id IP identification number
	 * @param frag fragmentation bits and offset
	 * @param ttl time to live in the network
	 * @param prot upper layer protocol
	 * @param sum checksum (0 for libnet to autofill)
	 * @param src source IPv4 address (little endian)
	 * @param dst destination IPv4 address (little endian)
	 * @param payload optional payload or NULL
	 * @param payload_s payload length or 0
	 * @param l pointer to a libnet context
	 * @param ptag protocol tag to modify an existing header, 0 to build a new one
	 * @return protocol tag value on success, -1 on error
	 * libnet_ptag_t 
	 libnet_build_ipv4(u_int16_t len, u_int8_t tos, u_int16_t id, u_int16_t frag,
	 u_int8_t ttl, u_int8_t prot, u_int16_t sum, u_int32_t src, u_int32_t dst,
	 u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag);
	 */

	public native boolean libnet_build_ipv4(int len, int tos, int id, int frag, int ttl, int prot, int sum, int src, int dst, byte[] payload, int key);

	/**
	 * send the current configuration
	 * @param key - the instance key
	 * @return 0 on flase and !=0 otherwise
	 */
	public native int libnet_write(int key);

	/**
	 * release all resources.
	 * @param key
	 * @return
	 */
	public native int libnet_destroy(int key);

	/**
	 * @param key - the instance key
	 * @return the current statistics
	 */
	public native String get_statistics(int key);
}
