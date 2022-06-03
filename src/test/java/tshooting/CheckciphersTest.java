/**
* Tshooting tools.
* 
* <P>Tools for tshooting...
*  
@author Jerome Blomart
@version 0.1
*/
package tshooting;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.anyOf;


import java.util.AbstractMap;
import java.util.Base64;
import java.util.Map.Entry;

import java.io.File;
import java.io.FileOutputStream;


import java.math.BigInteger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;



class SelfSignedCertificate {

    private static final String CERTIFICATE_ALIAS = "DUMMY";
    private static final String CERTIFICATE_ALGORITHM = "RSA";
    private static final String CERTIFICATE_DN = "CN=dummy";
    private static final String CERTIFICATE_NAME = "dummy";
    private static final int CERTIFICATE_BITS = 2048;
    
    static {
        // adds the Bouncy castle provider to java security
        Security.addProvider(new BouncyCastleProvider());
    }

    @SuppressWarnings("deprecation")
    public X509Certificate createCertificateFile(String filename) throws Exception{
        X509Certificate cert = null;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CERTIFICATE_ALGORITHM);
        keyPairGenerator.initialize(CERTIFICATE_BITS, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // GENERATE THE X509 CERTIFICATE
        X509V3CertificateGenerator v3CertGen =  new X509V3CertificateGenerator();
        v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        v3CertGen.setIssuerDN(new X509Principal(CERTIFICATE_DN));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*10)));
        v3CertGen.setSubjectDN(new X509Principal(CERTIFICATE_DN));
        v3CertGen.setPublicKey(keyPair.getPublic());
        v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        cert = v3CertGen.generateX509Certificate(keyPair.getPrivate());
        saveCert(cert,filename);
        return cert;
    }

    @SuppressWarnings("deprecation")
    public X509Certificate createCertificate() throws Exception{
        X509Certificate cert = null;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CERTIFICATE_ALGORITHM);
        keyPairGenerator.initialize(CERTIFICATE_BITS, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // GENERATE THE X509 CERTIFICATE
        X509V3CertificateGenerator v3CertGen =  new X509V3CertificateGenerator();
        v3CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        v3CertGen.setIssuerDN(new X509Principal(CERTIFICATE_DN));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*10)));
        v3CertGen.setSubjectDN(new X509Principal(CERTIFICATE_DN));
        v3CertGen.setPublicKey(keyPair.getPublic());
        v3CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        cert = v3CertGen.generateX509Certificate(keyPair.getPrivate());
        saveCert(cert,keyPair.getPrivate());
        return cert;
    }

    private void saveCert(X509Certificate cert, String filename) throws Exception {
        final FileOutputStream os = new FileOutputStream(filename);
        os.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
        String[] chunks = Base64.getEncoder().encodeToString(cert.getEncoded()).split("(?<=\\G.{64})");
        for (Integer i = 0; i < chunks.length; i++) {
            String line = chunks[i] + "\n";
            os.write(line.getBytes("US-ASCII"));
        }
        os.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
        os.close();
    }

    private void saveCert(X509Certificate cert, PrivateKey key) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");    
        keyStore.load(null, null);
        keyStore.setKeyEntry(CERTIFICATE_ALIAS, key, "YOUR_PASSWORD".toCharArray(),  new java.security.cert.Certificate[]{cert});
        File file = new File(".", CERTIFICATE_NAME);
        keyStore.store( new FileOutputStream(file), "YOUR_PASSWORD".toCharArray() );
    }
}

/**
* CheckCiphers Unit Tests .
* 
* <P>Tests different cases of SSL connections ...
*  
@author Jerome Blomart
@version 0.1
*/
public class CheckciphersTest {
    private Checkciphers cipherschecker = new Checkciphers();
    
    @Before
    public void setup() {
    }

    @After
    public void unset() {
    }

    /**
     * Tests that listing ciphers form jdk shows the correct cipher.
     */
    @Test
    public void doCheckShowsCipher() {
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("TLS_RSA_WITH_AES_256_GCM_SHA384"));
    }
    
    /**
     * Tests that connecting to github.com using specific cipher succeeds.
     */
    @Test
    public void doCheckShowsSuccess() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("Successfully connected."));
    }
    
    /**
     * Tests that connecting to github.com with specific cipher shows TLS version of the handshake.
     */
    @Test
    public void doCheckShowsTls(){
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("Tls Version : TLSv1.2"));
    }

    /**
     * Tests that connecting to github.com with specific cipher shows Peer Certificates list.
     */
    @Test
    public void doCheckShowsSuccessPeerCerts() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("Peer Certificates :"));
    }
    
    /**
     * Tests that connecting to github.com with specific cipher shows Full Peer Certificates.
     */
    @Test
    public void doCheckShowsSuccessFullPeerCerts() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("    Peer Certificate subject Principal : "));
        assertThat(output.getOutput(), containsString("    Peer Certificate Subject Alertnate Names : "));
        assertThat(output.getOutput(), containsString("    Peer Certificate Issuer : "));
        assertThat(output.getOutput(), containsString("    Peer Certificate Valid From : "));
        assertThat(output.getOutput(), containsString("    Peer Certificate Valid To : "));
    }

    /**
     * Tests that connecting to github.com with a custom CA cert shows the cert.
     */
    @Test
    public void doCheckShowsSuccessFullCustomCaCert() {
        try {
            (new SelfSignedCertificate()).createCertificateFile("dummy.crt");
        } catch (Exception e) {
            fail("Could not create dummy self signed certificate (" + e + ").");
        }
        cipherschecker.setServer("github.com");
        cipherschecker.setCa("dummy.crt");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        (new File("dummy.crt")).delete();
        cipherschecker.setCa(null);
        assertThat(output.getOutput(), containsString("    Certificate subject Principal : "));
        assertThat(output.getOutput(), containsString("    Certificate Subject Alertnate Names : "));
        assertThat(output.getOutput(), containsString("    Certificate Issuer : "));
        assertThat(output.getOutput(), containsString("    Certificate Valid From : "));
        assertThat(output.getOutput(), containsString("    Certificate Valid To : "));
    }

    /**
     * Tests that connecting to github with a low timeout ends with read timeout.
     */
    
    @Test
    public void doCheckShowsTimeoutFailure() {
        cipherschecker.setServer("github.com");
        cipherschecker.setTimeout(1);
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        cipherschecker.setTimeout(1000);
        assertThat(output.getOutput(), anyOf(containsString("Exception : java.net.SocketTimeoutException: Read timed out"), containsString("Exception : javax.net.ssl.SSLException: Read timed out")));
    }

    /**
     * Tests that connecting to inexistant dns name ends with unknown host exception.
     */
    @Test
    public void doCheckShowsSocketResetFailure() {
        cipherschecker.setServer("githubX.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("Exception : java.net.UnknownHostException"));

    }
    
    /**
     * Tests that connecting to github.com with renego shows no negociable cipher suite.
     */
    @Test
    public void doCheckShowsTlsNoCiphersFailure() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_EMPTY_RENEGOTIATION_INFO_SCSV",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("Exception : javax.net.ssl.SSLHandshakeException: No negotiable cipher suite"));
    }

    /**
     * Tests that connecting  to github.com with incorrect cipher ends with handshake failure.
     */
    @Test
    public void doCheckShowsHandshakeFailure() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        assertThat(output.getOutput(), containsString("Exception : javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure"));
    }

    /**
     * Tests that connecting to github.com with incorrect protocol (SSLv3) ends with No appropriate protocol.
     */
    @Test
    public void doCheckShowsNoProtocolsFailure() {
        cipherschecker.setServer("github.com");
        cipherschecker.setTlsVersion("SSLv3");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE, 1000);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) {}
        cipherschecker.setTlsVersion("TLSv1.2");
        assertThat(output.getOutput(), containsString("Exception : javax.net.ssl.SSLHandshakeException: No appropriate protocol (protocol is disabled or cipher suites are inappropriate)"));
    }
    
}