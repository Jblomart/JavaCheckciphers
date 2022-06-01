import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;

import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.security.cert.CertificateFactory;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import java.net.ConnectException;
import java.net.SocketException;
import javax.net.ssl.SSLHandshakeException;

public class Checkciphers
{
    public static void main(String[] args)
        throws Exception
    {
        String server =  null;
        Boolean verbose = Boolean.FALSE;
        Boolean untrusted = Boolean.FALSE;
        Boolean nohostnameval = Boolean.FALSE;
        Integer port = 443;
        List<String> allowedtlsversions = Arrays.asList(new String[] { "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2" });
        String tlsversion = "TLSv1.2";
        String cafile = null;
        Boolean customca = Boolean.FALSE;

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
                            if (args.length > i) {
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
                            if (args.length > i) {
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
                            if (args.length > i) {
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
                            if (args.length > i) {
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
                            if (args.length > i) {
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
                            if (args.length > i) {
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
                        case "no-hostname-validation":
                            nohostnameval = Boolean.TRUE;
                            break;
                        default:
                            throw new IllegalArgumentException("Unexpected argument " + arg + ".");
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected argument " + args[i].charAt(1) + ".");
                }
        }

        // list available ciphers
        SSLServerSocketFactory ssf = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();

        String[] defaultCiphers = ssf.getDefaultCipherSuites();
        String[] availableCiphers = ssf.getSupportedCipherSuites();

        TreeMap<String, Boolean> ciphers = new TreeMap<String, Boolean>();

        for(int i=0; i<availableCiphers.length; ++i )
            ciphers.put(availableCiphers[i], Boolean.FALSE);

        for(int i=0; i<defaultCiphers.length; ++i )
            ciphers.put(defaultCiphers[i], Boolean.TRUE);

        if (server == null) {
            System.out.println("Listing Default Ciphers :");
            System.out.println("-------------------------");
        } else {
            if (port != 443) {
                System.out.println("Testing Default Ciphers when connecting to " + server + " on port " + port.toString() + " :" );
                System.out.println("---------------------------------------------------------------------------------------------------");
            } else {
                System.out.println("Testing Default Ciphers when connecting to " + server + " :" );
                System.out.println("-----------------------------------------------------------------------------------------------");
            }
        }
        for(Iterator i = ciphers.entrySet().iterator(); i.hasNext(); ) {
            Map.Entry cipher=(Map.Entry)i.next();
            if(Boolean.TRUE.equals(cipher.getValue())) {
                String cipherstr = (String) cipher.getKey();
                if (server != null) {
                    System.out.println("- trying to connect using " + cipherstr + " :");
                    try {
                        String[] enabledciphers = {cipherstr};
                        String[] protocols = {tlsversion};
                        SSLSocketFactory sslsocketfactory = null;

                        if (untrusted || customca) {
                            TrustManager[] trustCerts;
                            if (untrusted) {
                                trustCerts = new TrustManager[] { new X509TrustManager() {
                                    public X509Certificate[] getAcceptedIssuers() {
                                        return null;
                                    }
                                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                    }
                                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                    }
                                } };
                            } else {
                                CertificateFactory fac = CertificateFactory.getInstance("X509");
                                FileInputStream is = new FileInputStream(cafile);
                                X509Certificate cert = (X509Certificate) fac.generateCertificate(is);
                                trustCerts = new TrustManager[] { new X509TrustManager() {
                                    public X509Certificate[] getAcceptedIssuers() {
                                        return null;
                                    }
                                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                    }
                                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                    }
                                } };
                            }
                            SSLContext sc = SSLContext.getInstance("SSL");
                            sc.init(null, trustCerts, new SecureRandom());
                            sslsocketfactory = (SSLSocketFactory) sc.getSocketFactory();
                            sslsocketfactory.getDefault();
                        } else {
                            sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                        }

                        SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(server, port);

                        if (verbose) {
                            System.out.println("  Socket connected.");
                        }

                        SSLParameters sslparams = new SSLParameters();
                        if (untrusted || nohostnameval) {
                            sslparams.setEndpointIdentificationAlgorithm(null);
                        } else {
                            sslparams.setEndpointIdentificationAlgorithm("HTTPS");
                        }
                        sslsocket.setSSLParameters(sslparams);
                        sslsocket.setEnabledCipherSuites(enabledciphers);
                        sslsocket.setEnabledProtocols(protocols);

                        if (verbose) {
                            System.out.println("  Handshake succeeded.");
                        }

                        InputStream in = sslsocket.getInputStream();
                        OutputStream out = sslsocket.getOutputStream();

                        // Write a test byte to get a reaction :)
                        out.write(1);

                        while (in.available() > 0) {
                            System.out.print(in.read());
                        }
                        System.out.println("  Successfully connected.");
                    } catch (ConnectException exception) {
                        if (verbose) {
                            System.out.println("  Failed to connect.");
                            System.out.println();
                            exception.printStackTrace();
                        } else {
                            System.out.println("  Failed to connect. (" + exception + ")");
                        }
                        System.exit(1);
                    } catch (SocketException exception) {
                        if (verbose) {
                            System.out.println();
                            exception.printStackTrace();
                            System.out.println();
                        } else {
                            System.out.println("  Failed to connect. (" + exception + ")");
                        }
                    } catch (SSLHandshakeException exception) {
                        if (verbose) {
                            System.out.println();
                            exception.printStackTrace();
                            System.out.println();
                        } else {
                            System.out.println("  Failed to connect. (" + exception + ")");
                        }
                    } catch (Exception exception) {
                        if (verbose) {
                            System.out.println();
                            exception.printStackTrace();
                        } else {
                            System.out.println("  Failed to connect. (" + exception + ")");
                        }
                        System.exit(1);
                    }
                } else {
                    System.out.println("- " + cipherstr);
                }
            }
        }
    }
}