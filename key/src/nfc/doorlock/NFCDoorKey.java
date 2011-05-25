package nfc.doorlock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.Iterator;
import java.security.Provider;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.nfc.tech.NfcF;
import android.os.Bundle;
import android.widget.TextView;
import android.util.Log;
//import android.app.Activity;
import android.os.Bundle;


public class NFCDoorKey extends Activity {
	private NfcAdapter mAdapter;
	private PendingIntent mPendingIntent;
	private IntentFilter[] mFilters;
	private String[][] mTechLists;
	private TextView mText;
	private int mCount = 0;
	public static int MAX_FRAME = 250;
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
    	super.onCreate(savedInstanceState);

		setContentView(R.layout.main);
		mText = (TextView) findViewById(R.id.text);
		mText.setText("Scan a tag");

		mAdapter = NfcAdapter.getDefaultAdapter(this);

		// Create a generic PendingIntent that will be deliver to this activity.
		// The NFC stack
		// will fill in the intent with the details of the discovered tag before
		// delivering to
		// this activity.
		mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
				getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

		// Setup an intent filter for all MIME based dispatches
		IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
		try {
			ndef.addDataType("*/*");
		} catch (MalformedMimeTypeException e) {
			throw new RuntimeException("fail", e);
		}
		mFilters = new IntentFilter[] { ndef, };

		// Setup a tech list for all NfcF tags
		mTechLists = new String[][] { new String[] { NfcA.class.getName() } };

		// X509Certificate

		Log.d("NFCDoorKey", "End of setup");
		//openFileOutput
		/*StringBuilder key = new StringBuilder();
		 
		key.append("-----BEGIN PRIVATE KEY-----\n");
		key.append("MGACAQAwEAYHKoZIzj0CAQYFK4EEAB4ESTBHAgEBBBRpmjAINb+1Ykcin0kC7iW6\n");
		key.append("BbeLBKEsAyoABC5DFE397JAT7ghlXT4Umuby16C+ut40newX2r7yBgag/SA1Ji+N\n");
		key.append("Dlg=\n");
		key.append("-----END PRIVATE KEY-----\n");*/
		
		/*key.append("-----BEGIN PRIVATE KEY-----\n");
		key.append("MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQCprsFPMnLTv9ClaPRGHJYnEiWk\n");
		key.append("QvQiusxZsr3gvwGOrWPf27qHV+omN3fQApHmJSaiJhXkkYgR6suHwpo+zV+V7qfL\n");
		key.append("oB3Mp4WAByVzDPZLjxYSlzoxwpUuOyabZV422tqIUWuCAJsuVM3ZMaUS5BpWtTnS\n");
		key.append("HV6yGvyt65HWCIYcfT5+j8rEbiVKvlvsIxqzWDjsnYZ/yziDg30pSZLwULVv9UU6\n");
		key.append("EYQwr/N3ngnO2JmXDrhewci8lCyDbBtoxYkGob0RbVzFtQTYyvXwL6lP6CHx5BXt\n");
		key.append("6ptEz6iH2H0j8pjb4AFF6OBTdwyy0EUYwMnX4uEXYdQF8ZPZZtUvNs3PwhwrAiEA\n");
		key.append("wnHk6Kn6r/wfdVZFXzoOkXkYyvGPLQKV6NX7Y/1bgYsCggEATFOvxFTwOhZKsSRn\n");
		key.append("R4IrWneag2dVgAW+PNB5aUQ6laHHg8M8+fzA4vd8OWfEbdHcUNVOnncD98Vpgz6I\n");
		key.append("QXENsA3V3TOaJIG1qgcVI3afJLeqbWVE8xK+hxe91YAyd9M25C9/WQ8+Sihjw5Nq\n");
		key.append("/+gFFSvpQ+1ZbaJ5UmkbGmbUeP2egLAU5E/MQadCbsbZZr1hslg6hGYw4HaL4MXP\n");
		key.append("DbRrME11bakmexoX5V9ddlXlK4P1Zya2EWuqcKHi9cs2mEY3OybIfrbwJ68ovP0E\n");
		key.append("sw2YEuCkmV99mbeK12OPiqTkMDxhERPuZIpbdgolJ8ZEqPFM2yfi5r1+mQcHmV5T\n");
		key.append("7enAywQiAiBidiHFqVWHFQaWPvekKz0+sH4LfE6jdaA5VkvBxgGzUA==\n");
		key.append("-----END PRIVATE KEY-----\n");*/
		
		/*StringBuilder cert = new StringBuilder();
		cert.append("-----BEGIN CERTIFICATE-----\n");
		cert.append("MIIC0DCCApCgAwIBAgIBAjAJBgcqhkjOPQQBMIGCMQswCQYDVQQGEwJVSzEPMA0G\n");
		cert.append("A1UECBMGU3VycmV5MQ4wDAYDVQQHEwVFZ2hhbjEUMBIGA1UEChMLRXhhbXBsZSBJ\n");
		cert.append("bmMxHDAaBgNVBAMTE0V4YW1wbGUgSW5jIFJvb3QgQ0ExHjAcBgkqhkiG9w0BCQEW\n");
		cert.append("D2Rvb3JAbG9jay5jby51azAeFw0xMTA1MjQxNTU4MzFaFw0xMjA1MjMxNTU4MzFa\n");
		cert.append("MG8xCzAJBgNVBAYTAlVLMQ8wDQYDVQQIEwZTdXJyZXkxFDASBgNVBAoTC0V4YW1w\n");
		cert.append("bGUgSW5jMRowGAYDVQQDExFFeGFtcGxlIEluYyBQaG9uZTEdMBsGCSqGSIb3DQEJ\n");
		cert.append("ARYOZG9vckBrZXkuY28udWswPjAQBgcqhkjOPQIBBgUrgQQAHgMqAAQuQxRN/eyQ\n");
		cert.append("E+4IZV0+FJrm8tegvrreNJ3sF9q+8gYGoP0gNSYvjQ5Yo4IBIzCCAR8wCQYDVR0T\n");
		cert.append("BAIwADAdBgNVHQ4EFgQUEq7twDeJ4lFdMSwFYcmy8tOrUPkwgbcGA1UdIwSBrzCB\n");
		cert.append("rIAUap0KfwksO2bZ8JPVHnJMdpvvT9ehgYikgYUwgYIxCzAJBgNVBAYTAlVLMQ8w\n");
		cert.append("DQYDVQQIEwZTdXJyZXkxDjAMBgNVBAcTBUVnaGFuMRQwEgYDVQQKEwtFeGFtcGxl\n");
		cert.append("IEluYzEcMBoGA1UEAxMTRXhhbXBsZSBJbmMgUm9vdCBDQTEeMBwGCSqGSIb3DQEJ\n");
		cert.append("ARYPZG9vckBsb2NrLmNvLnVrggkAjLhK2ePoLKcwOQYJYIZIAYb4QgEEBCwWKmh0\n");
		cert.append("dHBzOi8vd3d3LmV4YW1wbGUuY29tL2V4YW1wbGUtY2EtY3JsLnBlbTAJBgcqhkjO\n");
		cert.append("PQQBAy8AMCwCFDP94U2ASA9kCxy+rCHVyUhTAkaQAhQthLNMpH/OhCdtWbhKqKz6\n");
		cert.append("WU47VA==\n");
		cert.append("-----END CERTIFICATE-----\n");*/
		/*cert.append("-----BEGIN CERTIFICATE-----\n");
		cert.append("MIIF8zCCBZqgAwIBAgIBATAJBgcqhkjOOAQDMIGCMQswCQYDVQQGEwJVSzEPMA0G\n");
		cert.append("A1UECBMGU3VycmV5MQ4wDAYDVQQHEwVFZ2hhbjEUMBIGA1UEChMLRXhhbXBsZSBJ\n");
		cert.append("bmMxHDAaBgNVBAMTE0V4YW1wbGUgSW5jIFJvb3QgQ0ExHjAcBgkqhkiG9w0BCQEW\n");
		cert.append("D2Rvb3JAbG9jay5jby51azAeFw0xMTA1MjIxMDE0MDBaFw0xMjA1MjExMDE0MDBa\n");
		cert.append("MG8xCzAJBgNVBAYTAlVLMQ8wDQYDVQQIEwZTdXJyZXkxFDASBgNVBAoTC0V4YW1w\n");
		cert.append("bGUgSW5jMRowGAYDVQQDExFFeGFtcGxlIEluYyBQaG9uZTEdMBsGCSqGSIb3DQEJ\n");
		cert.append("ARYOZG9vckBrZXkuY28udWswggNGMIICOQYHKoZIzjgEATCCAiwCggEBAKmuwU8y\n");
		cert.append("ctO/0KVo9EYclicSJaRC9CK6zFmyveC/AY6tY9/buodX6iY3d9ACkeYlJqImFeSR\n");
		cert.append("iBHqy4fCmj7NX5Xup8ugHcynhYAHJXMM9kuPFhKXOjHClS47JptlXjba2ohRa4IA\n");
		cert.append("my5UzdkxpRLkGla1OdIdXrIa/K3rkdYIhhx9Pn6PysRuJUq+W+wjGrNYOOydhn/L\n");
		cert.append("OIODfSlJkvBQtW/1RToRhDCv83eeCc7YmZcOuF7ByLyULINsG2jFiQahvRFtXMW1\n");
		cert.append("BNjK9fAvqU/oIfHkFe3qm0TPqIfYfSPymNvgAUXo4FN3DLLQRRjAydfi4Rdh1AXx\n");
		cert.append("k9lm1S82zc/CHCsCIQDCceToqfqv/B91VkVfOg6ReRjK8Y8tApXo1ftj/VuBiwKC\n");
		cert.append("AQBMU6/EVPA6FkqxJGdHgitad5qDZ1WABb480HlpRDqVoceDwzz5/MDi93w5Z8Rt\n");
		cert.append("0dxQ1U6edwP3xWmDPohBcQ2wDdXdM5okgbWqBxUjdp8kt6ptZUTzEr6HF73VgDJ3\n");
		cert.append("0zbkL39ZDz5KKGPDk2r/6AUVK+lD7VltonlSaRsaZtR4/Z6AsBTkT8xBp0Juxtlm\n");
		cert.append("vWGyWDqEZjDgdovgxc8NtGswTXVtqSZ7GhflX112VeUrg/VnJrYRa6pwoeL1yzaY\n");
		cert.append("Rjc7Jsh+tvAnryi8/QSzDZgS4KSZX32Zt4rXY4+KpOQwPGERE+5kilt2CiUnxkSo\n");
		cert.append("8UzbJ+LmvX6ZBweZXlPt6cDLA4IBBQACggEALY81P/Elk+vWSE5uLtQzkL1pPvZE\n");
		cert.append("u8N4RwKe7pV+hwSfiQHsymCLGpb5uc9+G+D8l5JPzuaXFSCioHsjc7pqC2G45eRU\n");
		cert.append("S0v1wt71HeZHXrmuBSw+7S0snLVGUDVK6VVb7bIexR7DIVsc8rjzy4nnjgRdgKcD\n");
		cert.append("y0/CnvMuaew0JG84V6DYEHhdAjr6ZUJsGd9J03uUpLDVoq7FrjtgUBIAHm2e7Sdu\n");
		cert.append("xWlQll3mEOSUsZuzbPJf/fayMU64s42kr1CKAjlhp/6WWZIk0pNTSbzZDU4B332b\n");
		cert.append("tkbVAw51USH5H8JRLRwXvPtBX5mra2eHQ+Acvna+IBZT6gBcdQNs1ea6eaOCASMw\n");
		cert.append("ggEfMAkGA1UdEwQCMAAwHQYDVR0OBBYEFDM3xjuegLeldTSKoWrpvqqG76x/MIG3\n");
		cert.append("BgNVHSMEga8wgayAFPqE91kM2SnZVxmAKRZXQX7Ie3kyoYGIpIGFMIGCMQswCQYD\n");
		cert.append("VQQGEwJVSzEPMA0GA1UECBMGU3VycmV5MQ4wDAYDVQQHEwVFZ2hhbjEUMBIGA1UE\n");
		cert.append("ChMLRXhhbXBsZSBJbmMxHDAaBgNVBAMTE0V4YW1wbGUgSW5jIFJvb3QgQ0ExHjAc\n");
		cert.append("BgkqhkiG9w0BCQEWD2Rvb3JAbG9jay5jby51a4IJALctsSKszsYoMDkGCWCGSAGG\n");
		cert.append("+EIBBAQsFipodHRwczovL3d3dy5leGFtcGxlLmNvbS9leGFtcGxlLWNhLWNybC5w\n");
		cert.append("ZW0wCQYHKoZIzjgEAwNIADBFAiAFm9uXUMFgEwVm2xVtyFBa3pNVkwfw/IbIXGTc\n");
		cert.append("Ucw5lAIhAIrumridXwSS1Q1dRxYaEhUxt9HGjahP+wC6lKf6hfuU\n");
		cert.append("-----END CERTIFICATE-----\n");*/
		
		/*try
		{
			Log.d("NFCDoorKey", "Writing Key");
			FileOutputStream out = openFileOutput ("door.key", 0);
			out.write(key.toString().getBytes());
			out.close();
			Log.d("NFCDoorKey", "Writing Cert");
			out = openFileOutput ("door.crt", 0);
			out.write(cert.toString().getBytes());
			out.close();
		} catch (Exception e)
		{
			Log.d("NFCDoorKey", e.getMessage());
		}*/
    }
    

	@Override
	public void onResume() {
		super.onResume();
		Log.d("NFCDoorKey", "Foreground NFC dispatch enabled");
		mAdapter.enableForegroundDispatch(this, mPendingIntent, null, null);
	}

	@Override
	public void onNewIntent(Intent intent) {
		Log.i("NFCDoorKey", "Discovered tag with intent: " + intent);
		// mText.setText("Discovered tag " + ++mCount + " with intent: " +
		// intent);
		Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		for (int i = 0; i < tagFromIntent.getTechList().length; i++) {
			Log.i("NFCDoorKey", tagFromIntent.getTechList()[i]);
		}
		IsoDep nfc = IsoDep.get(tagFromIntent);
		Log.i("NFCDoorKey", "Tag from intent!!");
		byte[] data = { (byte) 0xAF }; // Are you a door? open up
		
		byte[] returndata;
		try {
			nfc.connect();
			if (nfc.isConnected()) {
				Log.i("NFCDoorKey", "Begin transcevie");
				returndata = nfc.transceive(data);
				if (returndata[0] == (byte) 0x90 && returndata[1] == (byte) 0x00) // If door 
				{
					//byte[] doorid
					byte[] challenge = new byte[returndata.length - 2];
					System.arraycopy(returndata, 2, challenge, 0, challenge.length);
					
					Log.i("NFCDoorKey", "Door Found, ID: ");
					Log.i("NFCDoorKey", "Challenge received: " + challenge.length);
					// find correct key and cert for this door
					Log.i("NFCDoorKey", "Load Key");
					ByteArrayOutputStream output = new ByteArrayOutputStream();
					FileInputStream fis = openFileInput("door.key");
			        int size = (int)fis.getChannel().size();
					byte[] key = new byte[size];
					fis.read(key);
					String keystr = new String(key);
					keystr = keystr.replaceAll("-----BEGIN PRIVATE KEY-----\n", "");
					keystr = keystr.replaceAll("-----END PRIVATE KEY-----\n", "");
					byte[] keyBytes = android.util.Base64.decode(keystr,android.util.Base64.DEFAULT);
					fis.close();
					
					Log.i("NFCDoorKey", "Load Cert");
					fis = openFileInput("door.crt");
					Security.addProvider(new org.bouncycastle2.jce.provider.BouncyCastleProvider());
					CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC2");
					X509Certificate cert = (X509Certificate)cf.generateCertificate((InputStream)fis);
					fis.close();
					byte[] certificate = cert.getEncoded();
					
                    output.write((byte)0xAE);
                    byte blocks = (byte)(certificate.length/250);
                    byte overflow = (byte)(certificate.length%250);
                    output.write(blocks);
                    output.write((byte)MAX_FRAME);
                    output.write(overflow);
                    Log.i("NFCDoorKey", "Send Cert info, Length: " + certificate.length + ", Blocks: " + blocks + ", Blocksize: 250, Overflow: " + overflow);
                    returndata = nfc.transceive(output.toByteArray());
                    
                    Log.i("NFCDoorKey", "Send Cert");
					for (int i=0; i< blocks + 1; i++)
					{
						byte[] block = new byte[Math.min(MAX_FRAME, certificate.length - (i*MAX_FRAME))];
						if (block.length > 0)
						{
							System.arraycopy(certificate, i*MAX_FRAME, block, 0, block.length);
							Log.i("NFCDoorKey", "Send n bytes: " + block.length);
							nfc.transceive(block);
						}
					}
					
					Log.i("NFCDoorKey", "Load Algorithms");
					Log.i("NFCDoorKey", cert.getSigAlgName());
					
					KeyFactory keyFactory = KeyFactory.getInstance(cert.getPublicKey().getAlgorithm(), "BC2");
					PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
					PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
                    Signature s = Signature.getInstance(cert.getSigAlgName(), "BC2");
                    s.initSign(privateKey);
                    s.update(challenge);
                    byte[] sign = s.sign();
                    
					Log.i("NFCDoorKey", "Signature");
					output = new ByteArrayOutputStream();
					Log.i("NFCDoorKey", "Sig length " + sign.length);
                    output.write(sign);
                    returndata = nfc.transceive(output.toByteArray());
                    Log.i("NFCDoorKey", "Complete " + returndata[0]);

				} else {
					throw new IOException("not a door");
				}
			}
		} catch (Exception e) {
			Log.i("NFCDoorKey", e.getMessage());
			if (nfc.isConnected()) {
				try {
					nfc.close();
				} catch (IOException er) {

				}
			}
		}
	}

	@Override
	public void onPause() {
		super.onPause();
		mAdapter.disableForegroundDispatch(this);
	}
    
}
