control "V-27147" do
  title "Synchronize OS clocks with NTP"
  desc  "Synchronize operating system clocks with an organizational
authoritative source using NTP."
  impact 0.5
  tag "nist": ["AU-8 (1)", "Rev_3"]
  tag "severity": "medium"
  tag "rid": "SV-34446r1_rule"
  tag "stig_id": "SRG-APP-000117"
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
  tag "fix": "Depending on specific functional requirements of a concrete
production environment, the Red Hat Enterprise Linux 7 Server system can be
configured to utilize the services of theÃ\u0082Â chronydÃ\u0082Â NTP daemon
(the default), or services of theÃ\u0082Â ntpdÃ\u0082Â NTP daemon. Refer
toÃ\u0082Â https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/ch-Configuring_NTP_Using_the_chrony_Suite.htmlÃ\u0082Â for
more detailed comparison of the features of both of the choices, and for
further guidance how to choose between the two NTP daemons.

To specify a remote NTP server for time synchronization, perform the following:


* if the system is configured to use theÃ\u0082Â chronydÃ\u0082Â as the NTP
daemon (the default), edit the fileÃ\u0082Â /etc/chrony.confÃ\u0082Â as
follows,

* if the system is configured to use theÃ\u0082Â ntpdÃ\u0082Â as the NTP
daemon, edit the fileÃ\u0082Â /etc/ntp.confÃ\u0082Â as documented below.

Add or correct the following lines, substituting the IP or hostname of a remote
NTP server forÃ\u0082Â ntpserver:

server ntpserver

This instructs the NTP software to contact that remote server to obtain time
data."
end
