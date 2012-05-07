package edu.huji.cs.netutils.examples.speeddetector;
 
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import edu.huji.cs.netutils.NetUtilsException;
import edu.huji.cs.netutils.capture.JPCap;
import edu.huji.cs.netutils.parse.IPv4Address;
import edu.huji.cs.netutils.utils.IP;

public class SpeedDetectorFrame extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel jContentPane = null;
	private JTextArea myTextArea = null;
	private Gauge myGauge = null;
	
	private JPCap myJPCap = null;  //  @jve:decl-index=0:
	private ByteCounter myByteCounter = null;
	private Timer myTimer = new Timer();
	
	private float myMaxBandwith = 5000/8;

	public Gauge getMyGauge()
	{
		if(myGauge == null)
		{
			myGauge = new Gauge();
		}
		return myGauge;
	}

	/**
	 * This is the default constructor
	 * @throws NetUtilsException 
	 */
	public SpeedDetectorFrame() throws NetUtilsException {
		super();
		initialize();
		this.addWindowListener(new WindowListener() {
			
			@Override
			public void windowOpened(WindowEvent arg0) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void windowIconified(WindowEvent arg0) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void windowDeiconified(WindowEvent arg0) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void windowDeactivated(WindowEvent arg0) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void windowClosing(WindowEvent arg0) {
				if(myJPCap != null)
				{
					myJPCap.stopJPcap();
				}
				myTimer.cancel();
				System.exit(0);
				
			}
			
			@Override
			public void windowClosed(WindowEvent arg0) {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void windowActivated(WindowEvent arg0) {
				// TODO Auto-generated method stub
				
			}
		});
		startDetection();
	}

	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		this.setSize(300, 200);
		this.setContentPane(getJContentPane());
		this.setTitle("Speed Gauge ");
	}

	/**
	 * This method initializes jContentPane
	 * 
	 * @return javax.swing.JPanel
	 */
	private JPanel getJContentPane() {
		if (jContentPane == null) {
			jContentPane = new JPanel();
			jContentPane.setLayout(new BorderLayout());
			jContentPane.add(getMyTextArea(), BorderLayout.CENTER);
			jContentPane.add(getMyGauge(),BorderLayout.SOUTH);
		}
		return jContentPane;
	}

	/**
	 * This method initializes myTextArea	
	 * 	
	 * @return javax.swing.JTextArea	
	 */
	private JTextArea getMyTextArea() {
		if (myTextArea == null) {
			myTextArea = new JTextArea();
		}
		return myTextArea;
	}
	
	private void startDetection() throws NetUtilsException
	{
		// open sniffer on the first interface found
		myJPCap = new JPCap();
		
		myByteCounter = new ByteCounter(new IPv4Address(myJPCap.getmyInterfaceIp()));
					
		// create tcp listener
		myJPCap.addListener(myByteCounter);
		// start the sniffer
		myJPCap.startJPcap();
		
		myTimer.schedule(new TimerTask() {
			
			@Override
			public void run() {
				myByteCounter.update();
				myTextArea.setText(myByteCounter.toString());
				System.out.println( (((float)myByteCounter.getMyTotalSpeedInBitsPerSecond())/myMaxBandwith)*100);
				myGauge.setCurrentAmount((int) ((((float)myByteCounter.getMyTotalSpeedInBitsPerSecond())/myMaxBandwith)*100));
			}
		},1000,1000);

	}
	
	public static void main(String[] args) throws NetUtilsException
	{
		SpeedDetectorFrame fm = new SpeedDetectorFrame();
		fm.setSize(new Dimension(400,200));
		
		fm.setVisible(true);
	}

}
