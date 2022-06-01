package tshooting;

import org.junit.Test;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.*;

import java.beans.Transient;
import java.util.AbstractMap;
import java.util.Map.Entry;

import tshooting.CheckResult;
import tshooting.Checkciphers;

public class CheckciphersTest {
    private Checkciphers cipherschecker = new Checkciphers();
    
    @Test
    public void doCheckShowsCipher() {
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) { }
        assertThat(output.getOutput(), containsString("TLS_RSA_WITH_AES_256_GCM_SHA384"));
    }
    
    @Test
    public void doCheckShowsSuccess() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) { }
        assertThat(output.getOutput(), containsString("Successfully connected."));
    }

    @Test
    public void doCheckShowsSuccessPeerCerts() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) { }
        assertThat(output.getOutput(), containsString("Peer Certificates :"));
    }
    
    /*
    @Test
    public void doCheckShowsSocketFailure() {
        cipherschecker.setServer("githubX.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) { }
        assertThat(output.getOutput(), containsString("Exception : java.net.SocketException: Connection reset"));
    }

    @Test
    public void doCheckShowsTlsNoCiphersFailure() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_EMPTY_RENEGOTIATION_INFO_SCSV",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) { }
        assertThat(output.getOutput(), containsString("Exception : javax.net.ssl.SSLHandshakeException: No negotiable cipher suite"));
    }

    @Test
    public void doCheckShowsHandshakeFailure() {
        cipherschecker.setServer("github.com");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) { }
        assertThat(output.getOutput(), containsString("Exception : javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure"));
    }

    @Test
    public void doCheckShowsNoProtocolsFailure() {
        cipherschecker.setServer("github.com");
        cipherschecker.setTlsVersion("SSLv3");
        CheckResult output = new CheckResult(Boolean.FALSE, Boolean.TRUE);
        Entry<String,Boolean> cipher = new AbstractMap.SimpleEntry<String,Boolean>("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",Boolean.TRUE);
        cipherschecker.docheck(cipher,output);
        try {
            output.acquire();
        } catch (InterruptedException e) { }
        assertThat(output.getOutput(), containsString("Exception : javax.net.ssl.SSLHandshakeException: No appropriate protocol (protocol is disabled or cipher suites are inappropriate)"));
    }*/
}