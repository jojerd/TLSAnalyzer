# TLSAnalyzer
Analyze Exchange SSL / TLS Protocols to Ensure Compliance

1.0 Initial Release 10/20/2020

I created this script to test servers that are not internet facing as there are a number of internet hosted services that test for these protocols and cipher suites. However when troubleshooting Exchange OnPrem to Exchange Online connectivity and the firewall is locked down to only accept connections from Exchange Online servers we need a quick way to check enabled protocols. 

The script is used to create a secure channel connection with each protocol to each server that is returned in a given Active Directory Site. 
It will generate a CSV file of results from each server that is tested detailing the protocols that it was able to utilize in order to make a secure channel connection.
I have it checking for SSL2.0 SSL3.0 TLS1.0 TLS1.1 TLS1.2 and TLS1.3. 

Exchange 2013/2016/2019 is not able to utilize TLS 1.3 yet. TLS 1.3 will be supported at some point in the future but its currently in testing.

The limitations of this script are that I am not able to retrieve the given cipher suites per connection. For that you may want to utilize a Linux/BSD shell utility called testssl.

linked here: https://github.com/drwetter/testssl.sh

# Requirements
Administrative Privileges, PowerShell 3.0.



