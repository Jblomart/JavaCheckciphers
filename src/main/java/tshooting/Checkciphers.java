/**
* Tshooting tools.
* 
* <P>Tools for tshooting...
*  
@author Jerome Blomart
@version 0.1
*/
package tshooting;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;

import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.List;
import java.util.ListIterator;
import java.util.ArrayList;
import java.util.Arrays;

import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLHandshakeException;

import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.Certificate;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
* Handler for tls handshakes.
* 
* <P>Updates results with TLS version used and peer certificates.
*  
@author Jerome Blomart
@version 0.1
*/
final class HandShakeListener implements HandshakeCompletedListener {
    CheckResult result;

    /**
     * Constructor 
     * 
     * @param result <code>CheckResult</code> CheckResult object to store request results.
     */
    public HandShakeListener(CheckResult result) {
        this.result = result;
    }

    /**
     * Handshake completed listener. Updates results and releases Semaphore.
     */
    @Override
    public void handshakeCompleted(HandshakeCompletedEvent hce) {
        if (!this.result.getSummary() && this.result.getVerbose()) {
            this.result.appendOutputStr("  Handshake Succeeded.");
            this.result.appendOutputStr("  Peer Certificates :");
            try {
                Certificate[] peercerts = hce.getPeerCertificates();
                for (Integer j = 0; j < peercerts.length; j++){
                    X509Certificate pcert = (X509Certificate) peercerts[j];
                    if (j != 0) {
                        this.result.appendOutputStr("  ----");
                    }
                    this.result.appendOutputStr("    Peer Certificate subject Principal : " + pcert.getSubjectX500Principal());
                    this.result.appendOutputStr("    Peer Certificate Subject Alertnate Names : " + pcert.getSubjectAlternativeNames());
                    this.result.appendOutputStr("    Peer Certificate Issuer : " + pcert.getIssuerX500Principal());
                    this.result.appendOutputStr("    Peer Certificate Valid From : " + pcert.getNotBefore());
                    this.result.appendOutputStr("    Peer Certificate Valid To : " + pcert.getNotAfter());
                }
            } catch (SSLPeerUnverifiedException e) { 
            } catch (CertificateParsingException e) { }
            this.result.appendOutputStr("  Tls Version : " + hce.getSession().getProtocol());
        }
        this.result.getAvailable().release();
    }
}

/**
* Checkciphers.
* 
* <P>Tool to verify available ciphers agains a ssl server.
*  
@author Jerome Blomart
@version 0.1
*/
public class Checkciphers
{
    static Integer timeout = 1000;
    static String server =  null;
    static Boolean verbose = Boolean.FALSE;
    static Boolean untrusted = Boolean.FALSE;
    static Boolean nohostnameval = Boolean.FALSE;
    static Integer port = 443;
    static List<String> allowedtlsversions = Arrays.asList(new String[] { "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2" });
    static String tlsversion = null;
    static String cafile = null;
    static Boolean customca = Boolean.FALSE;
    static Boolean summary = Boolean.FALSE;
    static TreeMap<String, Boolean> ciphers = new TreeMap<String, Boolean>();
    static X509Certificate[] certs = null;
    static TreeMap<String,List<String>> results = new TreeMap<String,List<String>>();

    /**
     * helper function used for unit testing.
     * 
     * <P> Set server 
     * 
     * @param in_server <code>String</code> Server name or ip address.
     */
    public void setServer(String in_server) {
        server = in_server;
    }

    /**
     * helper function used for unit testing.
     * 
     * <P> Set port
     * 
     * @param in_port <code>Integer</code> Tcp port.
     */
    public void setPort(Integer in_port) {
        port = in_port;
    }

    /**
     * helper function used for unit testing.
     * 
     * <P> Set untrusted ssl connection
     * 
     * @param in_untrusted <code>Boolean</code> Do (not) validate certificates on ssl connection.
     */
    public void setUntrusted(Boolean in_untrusted) {
        untrusted = in_untrusted;
    }

    /**
     * helper function used for unit testing.
     * 
     * <P> Set endpointIdentification
     * 
     * @param in_endpointIdentification <code>Boolean</code> Do (not) validate endpoint identification.
     */
    public void setendpointIdentification(Boolean in_endpointIdentification) {
        nohostnameval = in_endpointIdentification;
    }

    /**
     * helper function used for unit testing.
     * 
     * <P> Set tls version
     * 
     * @param in_tlsversion <code>String</codde> Tls version string to use.
     */
    public void setTlsVersion(String in_tlsversion) {
        tlsversion = in_tlsversion;
    }

    /** 
     * helpder function used for unit testing.
     * 
     * <P> Set CA certificate file
     * 
     * @param in_cafile <code>String</code> Path to CA certificate.
     */
    public void setCa(String in_cafile) {
        customca = Boolean.TRUE;
        cafile = in_cafile;
    }

    /**
     * helper function used for unit testing.
     * 
     * <P> Set timeout
     * 
     * @param in_timeout <code>Integer</code> Timeout in ms for socket connection.
     */
    public void setTimeout(Integer in_timeout) {
        timeout = in_timeout;
    }

    /**
     * Convert a stacktrace to string.
     * 
     * <P> Note : removes the last newline in the converted string.
     *  
     * @param throwable
     * @return <code>String</code> String representation of the stack trace.
     */
    private static String convertStackTraceToString(Throwable throwable) {
        try (StringWriter sw = new StringWriter(); 
                PrintWriter pw = new PrintWriter(sw)) 
        {
            throwable.printStackTrace(pw);
            String stackstr = sw.toString();
            return stackstr.substring(0,stackstr.length()-1);
        } 
        catch (IOException ioe) 
        {
            throw new IllegalStateException(ioe);
        }
    }

    /**
     * Process command line arguments.
     * 
     * <P> Notte : throws illegal argument exceptions if unexpected arguments are found.
     * 
     * @param args <code>String[]</code> List of arguments as Strings.
     */
    private static void checkargs(String[] args)
    {
        for (int i=0; i < args.length; i++) {
            switch (args[i].charAt(0)) {
                case '-':
                    String arg = null;
                    if (args[i].charAt(1) == '-') {
                        String argstring = args[i].toString();
                        Integer len = argstring.length();
                        arg = argstring.substring(2, len);
                    } else {
                        arg = String.valueOf(args[i].charAt(1));
                    }
                    switch (arg) {
                        case "s":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                server = args[i+1];
                            } else {
                                throw new IllegalArgumentException("Server argument needs an string input. No input found.");
                            }
                            i+=1;
                            break;
                        case "server":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                server = args[i+1];
                            } else {
                                throw new IllegalArgumentException("Server argument needs an string input. No input found.");
                            }
                            i+=1;
                            break;
                        case "p":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                try {
                                    port = Integer.parseInt(args[i+1]);
                                } catch ( NumberFormatException e) {
                                    throw new IllegalArgumentException("Server argument needs an Integer input.");
                                }
                            } else {
                                throw new IllegalArgumentException("Port argument needs an Integer input. No input found.");
                            }
                            i+=1;
                            break;
                        case "port":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                try {
                                    port = Integer.parseInt(args[i+1]);
                                } catch ( NumberFormatException e) {
                                    throw new IllegalArgumentException("Server argument needs an Integer input.");
                                }

                            } else {
                                throw new IllegalArgumentException("Port argument needs an Integer input. No input found.");
                            }
                            i+=1;
                            break;
                        case "t":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                if (allowedtlsversions.contains(args[i+1])) {
                                    tlsversion = args[i+1];
                                } else {
                                    throw new IllegalArgumentException("TlsVersion argument needs an String input equal to either SSLv3, TLSv1, TLSv1.1, TLSv1.2.");
                                }
                            } else {
                                throw new IllegalArgumentException("TlsVersion argument needs an String input equal to either SSLv3, TLSv1, TLSv1.1, TLSv1.2. No input found.");
                            }
                            i+=1;
                            break;
                        case "tlsversion":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                if (allowedtlsversions.contains(args[i+1])) {
                                    tlsversion = args[i+1];
                                } else {
                                    throw new IllegalArgumentException("TlsVersion argument needs an String input equal to either SSLv3, TLSv1, TLSv1.1, TLSv1.2.");
                                }
                            } else {
                                throw new IllegalArgumentException("TlsVersion argument needs an String input equal to either SSLv3, TLSv1, TLSv1.1, TLSv1.2. No input found.");
                            }
                            i+=1;
                            break;
                        case "c":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                Path path = Paths.get(args[i+1]);
                                if (Files.exists(path)) {
                                    if (Files.isReadable(path)) {
                                        cafile = args[i+1];
                                        customca = Boolean.TRUE;
                                    } else {
                                        throw new IllegalArgumentException("CA argument needs a File path as argument. Could not read CA file.");
                                    }
                                } else {
                                    throw new IllegalArgumentException("CA argument needs a File path as argument. File not found.");
                                }
                            } else {
                                throw new IllegalArgumentException("CA argument needs a File path as argument. No input found.");
                            }
                            i+=1;
                            break;
                        case "ca":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                Path path = Paths.get(args[i+1]);
                                if (Files.exists(path)) {
                                    if (Files.isReadable(path)) {
                                        cafile = args[i+1];
                                        customca = Boolean.TRUE;
                                    } else {
                                        throw new IllegalArgumentException("CA argument needs a File path as argument. Could not read CA file.");
                                    }
                                } else {
                                    throw new IllegalArgumentException("CA argument needs a File path as argument. File not found.");
                                }
                            } else {
                                throw new IllegalArgumentException("CA argument needs a File path as argument. No input found.");
                            }
                            i+=1;
                            break;
                        case "v":
                            verbose = Boolean.TRUE;
                            break;
                        case "verbose":
                            verbose = Boolean.TRUE;
                            break;
                        case "u":
                            untrusted = Boolean.TRUE;
                            break;
                        case "untrusted":
                            untrusted = Boolean.TRUE;
                            break;
                        case "no-endpoint-identification":
                            nohostnameval = Boolean.TRUE;
                            break;
                        case "summary":
                            summary = Boolean.TRUE;
                            break;
                        case "h":
                            showusage();
                            System.exit(0);
                            break;
                        case "help":
                            showusage();
                            System.exit(0);
                            break;
                        case "timeout":
                            if (args.length > i && args[i+1].charAt(0) != '-') {
                                try {
                                    timeout = Integer.parseInt(args[i+1]);
                                } catch ( NumberFormatException e) {
                                    throw new IllegalArgumentException("Timeout argument needs an Integer input.");
                                }
                            } else {
                                throw new IllegalArgumentException("Timeout argument needs an Integer input. No input found.");
                            }
                            i+=1;
                            break;
                        default:
                            throw new IllegalArgumentException("Unexpected argument " + arg + ".");
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected argument " + args[i].charAt(1) + ".");
                }
        }

    }

    /**
     * Print usage.
     */
    private static void showusage() {
        System.out.println("Troubleshooting tool to list available Ciphers in current Java Runtime and test then against a Server.");
        System.out.println();
        System.out.println("Arguments :");
        System.out.println("-s|--server <value>\t\toptional\tDns name or Ip Address of the server to test ciphers against.");
        System.out.println("-p|--port <value>\t\toptional\tTCP port to use to connect to the server. Default value is 443.");
        System.out.println("-t|--tlsversion <value>\t\toptional\tTls version to use for handshake. Possible values are SSLv3, TLSv1, TLSv1.1, TLSv1.2.");
        System.out.println("-c|--ca <value>\t\t\toptional\tCA certificate in X509 format to use for validating Server Certificate.");
        System.out.println("-u|--untursted\t\t\toptional\tDo not validate Server Certificate.");
        System.out.println("-v|--verbose\t\t\toptional\tUse verbose logging.");
        System.out.println("-h|--help\t\t\toptional\tPrint this help message.");
        System.out.println("--no-endpoint-identification\toptional\tDo not check dns name or Certificate Subject Alternative Names.");
        System.out.println("--summary\t\t\toptional\tOutput summary only.");
        System.out.println("--timeout\t\t\toptional\tTimeout for connections in ms. Default value 1000 ms.");
    }

    /**
     * Print a string undelrined by "-" characters.
     * 
     * @param toprint <code>String</code> String to print underlined.
     */
    private static void printunderlined(String toprint) {
        Integer strlen = toprint.length();
        char[] charArray = new char[strlen];
        Arrays.fill(charArray, '-');
        String underlinestr = new String(charArray);
        System.out.println(toprint);
        System.out.println(underlinestr);
    }

    /**
     * Lists or checks a SSL cipher agains a SSL server.
     * 
     * <P> Note : uses a semaphore to avoid overlap in exception processing and in ssl handshake completed event.
     * 
     * @param cipher <code>Map.Entry<String,Boolean></code> String representation of the cipher to check.
     */
    public static void docheck(Map.Entry<String,Boolean> cipher, CheckResult output) {
        if(Boolean.TRUE.equals(cipher.getValue())) {
            // get the cipher string representation from input map.
            String cipherstr = (String) cipher.getKey();
            // if we have a Server configured then check this cipher agains the server.
            if (server != null) {
                // block till we know the handshake succeeded or failed.
                try {
                    output.acquire();
                } catch (InterruptedException e) {  }

                if (!output.getSummary()) {
                    output.appendOutputStr("- trying to connect using " + cipherstr + " :");
                }
                try {
                    // if a custom CA was provided read it a store in certs Certificate list
                    if (customca) {
                        CertificateFactory fac = CertificateFactory.getInstance("X509");
                        FileInputStream is = new FileInputStream(cafile);
                        certs = new X509Certificate[] {(X509Certificate) fac.generateCertificate(is)};
                        if (!output.getSummary() && output.getVerbose()) {
                            output.appendOutputStr("  Custom CA provided : using only provided CA for Certificate validation.");
                            output.appendOutputStr("    Certificate subject Principal : " + certs[0].getSubjectX500Principal());
                            output.appendOutputStr("    Certificate Subject Alertnate Names : " + certs[0].getSubjectAlternativeNames());
                            output.appendOutputStr("    Certificate Issuer : " + certs[0].getIssuerX500Principal());
                            output.appendOutputStr("    Certificate Valid From : " + certs[0].getNotBefore());
                            output.appendOutputStr("    Certificate Valid To : " + certs[0].getNotAfter());
                        }
                    }

                    // create the ssl socket factory with possiblity to trust all certs or to set custom CA to validate certs.
                    SSLSocketFactory sslsocketfactory = null;
                    if (untrusted || customca) {
                        TrustManager[] trustCerts;
                        if (untrusted) {
                            if (!output.getSummary() && output.getVerbose()) {
                                output.appendOutputStr("  Untrusted mode : disabling Certificate validations.");
                            }
                        }
                        trustCerts = new TrustManager[] { new X509TrustManager() {
                            public X509Certificate[] getAcceptedIssuers() {
                                return certs;
                            }
                            public void checkClientTrusted(X509Certificate[] certs, String authType) {
                            }
                            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                            }
                        } };
                        
                        SSLContext sc = SSLContext.getInstance("SSL");
                        sc.init(null, trustCerts, new SecureRandom());
                        sslsocketfactory = (SSLSocketFactory) sc.getSocketFactory();
                        SSLSocketFactory.getDefault();
                    } else {
                        sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();   
                    }

                    // create the ssl socket and add handshake completed listener (to know if handshake succeeded)
                    SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(server, port);
                    sslsocket.addHandshakeCompletedListener(new HandShakeListener(output));
                    sslsocket.setSoTimeout(timeout);
                    
                    // set ssl parameters to enable or disable endpoint identification and possibly set Tls version.
                    SSLParameters sslparams = new SSLParameters();
                    if (untrusted || nohostnameval) {
                        sslparams.setEndpointIdentificationAlgorithm(null);
                    } else {
                        sslparams.setEndpointIdentificationAlgorithm("HTTPS");
                    }
                    sslsocket.setSSLParameters(sslparams);
                    String[] enabledciphers = {cipherstr};
                    sslsocket.setEnabledCipherSuites(enabledciphers);
                    if (tlsversion != null) {
                        sslsocket.setEnabledProtocols(new String[] {tlsversion});
                    }

                    // open the socket
                    OutputStream out = sslsocket.getOutputStream();

                    // Write a test byte to get a reaction, confirms if the socket is opened (could have received RST).
                    out.write(1);

                    // Write outputs to output string.
                    if (!output.getSummary()) {
                        output.acquire();
                        output.appendOutputStr("  Successfully connected.");
                        output.release();
                    } else {
                        if (results.get("Successfully connected") != null) {
                            results.get("Successfully connected").add(cipherstr);
                        } else {
                            results.put("Successfully connected",new ArrayList<>(Arrays.asList(cipherstr)));
                        }
                    }
                } catch (ConnectException exception) {
                    // We failed to connect to the server. Exit completely , no need to check other ciphers it's dead.
                    if (output.getVerbose()) {
                        output.appendOutputStr("  Failed to connect.");
                        output.appendOutputStr("  Exception : " + convertStackTraceToString(exception).replace("\n","\n  "));
                    } else {
                        output.appendOutputStr("  Failed to connect. (" + exception + ")");
                    }
                    output.setFatalException();
                } catch (SocketException exception) {
                    // We most probably had a closed socket when we tried to write to it. Possibly RST received from server.
                    // Release the semaphore at the end of this as we will continue testing other ciphers.
                    if (!output.getSummary() && output.getVerbose()) {
                        output.appendOutputStr("  Failed socket.");
                        output.appendOutputStr("  Exception : " + convertStackTraceToString(exception).replace("\n","\n  "));
                    } else if (output.getSummary()) {
                        if (results.get(exception.toString()) != null) {
                            results.get(exception.toString()).add(cipherstr);
                        } else {
                            results.put(exception.toString(),new ArrayList<>(Arrays.asList(cipherstr)));
                        }
                    } else {
                        output.appendOutputStr("  Failed to connect. (" + exception + ")");
                    }
                    output.release();
                } catch (SSLHandshakeException exception) {
                    // SSL handshake failed.
                    // Release the semaphore at the end of this as we will continue testing other ciphers.
                    if (!output.getSummary() && output.getVerbose()) {
                        output.appendOutputStr("  Failed handshake.");
                        output.appendOutputStr("  Exception : " + convertStackTraceToString(exception).replace("\n","\n  "));
                    } else if (output.getSummary()) {
                        if (results.get(exception.toString()) != null) {
                            results.get(exception.toString()).add(cipherstr);
                        } else {
                            results.put(exception.toString(),new ArrayList<>(Arrays.asList(cipherstr)));
                        }
                    } else {
                        output.appendOutputStr("  Failed to connect. (" + exception + ")");
                    }
                    output.release();
                } catch (CertificateParsingException exception) {
                    // Could not parse the custom CA file passed through arguments. Exit completely , no need to check other ciphers it's dead.
                    if (output.getVerbose()) {
                        output.appendOutputStr("  Failed custom CA certificate format invalid.");
                        output.appendOutputStr("  Exception : " + convertStackTraceToString(exception).replace("\n","\n  "));
                    } else {
                        output.appendOutputStr("  Failed to connect. (" + exception + ")");
                    }
                    output.setFatalException();  
                } catch (UnknownHostException exception) {
                    // Could resolve host for provided server. Exit completely , no need to check other ciphers it's dead.
                    if (output.getVerbose()) {
                        output.appendOutputStr("  Could not resolve " + server + ".");
                        output.appendOutputStr("  Exception : " + convertStackTraceToString(exception).replace("\n","\n  "));
                    } else {
                        output.appendOutputStr("  Failed to connect. (" + exception + ")");
                    }
                    output.setFatalException();
                } catch (SocketTimeoutException exception) {
                    // Could resolve host for provided server. Exit completely , no need to check other ciphers it's dead.
                    if (output.getVerbose()) {
                        output.appendOutputStr("  Timeout connecting to " + server + ".");
                        output.appendOutputStr("  Exception : " + convertStackTraceToString(exception).replace("\n","\n  "));
                    } else {
                        output.appendOutputStr("  Failed to connect. (" + exception + ")");
                    }
                    output.setFatalException();
                } catch (Exception exception) {
                    // We received an exception that we did not excpet. Exit completely , no need to check other ciphers it's dead.
                    if (output.getVerbose()) {
                        output.appendOutputStr("  Failed uncatched exception.");
                        output.appendOutputStr("  Exception : " + convertStackTraceToString(exception).replace("\n","\n  "));
                    } else {
                        output.appendOutputStr("  Failed to connect. (" + exception + ")");
                    }
                    output.setFatalException();
                }
            } else {
                // just list the cipher in stdout.
                output.appendOutputStr("- " + cipherstr);
            }
        }
    }

    /**
     * Lists ciphers present in the Java Jdk and calls docheck for each of them.
     */
    private static void dochecks() {
        // list available ciphers
        SSLServerSocketFactory ssf = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();

        // list available and default ciphers.
        String[] defaultCiphers = ssf.getDefaultCipherSuites();
        String[] availableCiphers = ssf.getSupportedCipherSuites();
        for(int i=0; i<availableCiphers.length; ++i )
            ciphers.put(availableCiphers[i], Boolean.FALSE);
        for(int i=0; i<defaultCiphers.length; ++i )
            ciphers.put(defaultCiphers[i], Boolean.TRUE);

        // if no servers is given just list ciphers.
        if (server == null) {
            printunderlined("Listing Default Ciphers :");
        } else {
            if (port != 443) {
                printunderlined("Testing Default Ciphers when connecting to " + server + " on port " + port.toString() + " :" );
            } else {
                printunderlined("Testing Default Ciphers when connecting to " + server + " :" );
            }
        }

        // check each ciphers listed.
        for(Iterator<Map.Entry<String,Boolean>> i = ciphers.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry<String,Boolean> cipher=(Map.Entry<String,Boolean>) i.next();
            CheckResult output = new CheckResult(summary, verbose, timeout);
            docheck(cipher,output);
            try {
                output.acquire();
            } catch (InterruptedException e) { }
            if (output.getOutput().length() > 0) {
                System.out.println(output.getOutput());
            }
            if (output.getFatalException()) {
                System.exit(1);
            }
            output.release();
        }

        // output summary to stdout easier to list working ciphers this way.
        if (summary) {
            for(Iterator<Entry<String, List<String>>> i = results.entrySet().iterator(); i.hasNext();) {
                Entry<String,List<String>> result = (Entry<String,List<String>>) i.next();
                String resultkeystr = result.getKey();
                if (!resultkeystr.equals("Successfully connected")){
                    if (!verbose) {
                        continue;
                    }
                    resultkeystr = "Failed to connect : (" + resultkeystr + ")";
                }
                System.out.println("- " + resultkeystr + " :");
                for (ListIterator<String> j = result.getValue().listIterator(); j.hasNext();){
                    System.out.println("  " + j.next());
                }

            }
        }
    }

    /**
     * Main method : check arguments , show usage on exception and do the checks.
     * 
     * @param args <code>String[]</code> Command line arguments.
     */
    public static void main(String[] args)
    {
        // parse the command line arguments and print help if needed.
        try {
            checkargs(args);
        } catch (IllegalArgumentException exception){
            System.out.println("Argument Exception : " + exception);
            System.out.println();
            showusage();
            System.exit(1);
        }
        // do the ciphers checks
        dochecks();
    }
}