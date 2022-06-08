# Tool to check Java Jdk SSL Ciphers against a SSL server.

![Maven Build Workflow](https://github.com/j-blomart/JavaCheckciphers/actions/workflows/test-package.yaml/badge.svg)

## Usage : 

Command : `java -jar check-ciphers-0.1.0.jar -h`

Outputs : 
```
Troubleshooting tool to list available Ciphers in current Java Runtime and test then against a Server.

Arguments :
-s|--server <value>             optional        Dns name or Ip Address of the server to test ciphers against.
-p|--port <value>               optional        TCP port to use to connect to the server. Default value is 443.
-t|--tlsversion <value>         optional        Tls version to use for handshake. Possible values are SSLv3, TLSv1, TLSv1.1, TLSv1.2.
-c|--ca <value>                 optional        CA certificate in X509 format to use for validating Server Certificate.
-u|--untursted                  optional        Do not validate Server Certificate.
-v|--verbose                    optional        Use verbose logging.
-h|--help                       optional        Print this help message.
--no-endpoint-identification    optional        Do not check dns name or Certificate Subject Alternative Names.
--summary                       optional        Output summary only.
--timeout                       optional        Timeout for connections in ms. Default value 1000 ms.
--chiphers-exclude              optional        Exclude expression (comma separated values) from ciphers list.
```