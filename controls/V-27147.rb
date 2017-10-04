control "V-27147" do
  title "The application must synchronize with internal information system
clocks which in turn, are synchronized on an organizational-defined frequency
with an organizational-defined authoritative time source. "
  desc  "Synchronize operating system clocks with an organizational
authoritative source using NTP."
  impact 0.5
  tag "nist": ["AU-8 (1)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34446r1_rule"
  tag "gtitle": "SRG-APP-000117"
  tag "cci": "CCI-000160"
  tag "check": "To verify that a remote NTP service is configured for time
synchronization, open the following file:

/etc/chrony.conf

in the case the system in question is configured to use the chronyd as the NTP
daemon (default setting)

/etc/ntp.conf

 in the case the system in question is configured to use the ntpd as the NTP
daemon

In the file, there should be a section similar to the following:

server ntpserver

If this is not the case, this is a finding."
  tag "fix": "Depending on specific functional requirements of a concrete production
   environment, the Red Hat Enterprise Linux 7 Server system can be configured to 
   utilize the services of the chronyd NTP daemon (the default), or services of the
   ntpd NTP daemon. 
   Refer to https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/ch-Configuring_NTP_Using_the_chrony_Suite.html for more detailed comparison of the features of both of the choices, and for further guidance how to choose between the two NTP daemons.

To specify a remote NTP server for time synchronization, perform the following:

* if the system is configured to use the chronyd as the NTP daemon (the default),
 edit the file /etc/chrony.conf as follows,

* if the system is configured to use the ntpd as the NTP daemon, edit the file 
/etc/ntp.conf as documented below.

Add or correct the following lines, substituting the IP or hostname of a remote 
NTP server for ntpserver:

server ntpserver

This instructs the NTP software to contact that remote server to obtain time
data."
end
