/**
* Tshooting tools.
* 
* <P>Tools for tshooting...
*  
@author Jerome Blomart
@version 0.1
*/
package tshooting;

import org.junit.Ignore;
import org.junit.Test;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.junit.Assert.*;
import java.util.AbstractMap;
import java.util.Map.Entry;

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
        assertThat(output.getOutput(), containsString("Peer Certificate subject Principal : "));
        assertThat(output.getOutput(), containsString("Peer Certificate Subject Alertnate Names : "));
        assertThat(output.getOutput(), containsString("Peer Certificate Issuer : "));
        assertThat(output.getOutput(), containsString("Peer Certificate Valid From : "));
        assertThat(output.getOutput(), containsString("Peer Certificate Valid To : "));
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