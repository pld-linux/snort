Summary: packet-sniffer/logger
Name: snort
Version: 1.6.3
Release: 2
Copyright: GPL
Group: Applications/Internet
Source0: http://www.snort.org/Files/%{name}-%{version}.tar.gz
Source1: snort-stat
Source2: snortlog
Source3: snort-update
Source4: snortd
Source5: rules.base
Source6: README.snort-stuff
Source7: vision.rules
Url: http://www.snort.org
BuildRoot:  %{tmpdir}/%{name}-%{version}-root-%(id -u -n)
#Requires: libpcap >= 0.4
#BuildRequires: libpcap >= 0.4
BuildRequires: libpcap-static

%description
Snort is a libpcap-based packet sniffer/logger which 
can be used as a lightweight network intrusion detection system. 
It features rules based logging and can perform protocol analysis, 
content searching/matching and can be used to detect a variety of 
attacks and probes, such as buffer overflows, stealth port scans, 
CGI attacks, SMB probes, OS fingerprinting attempts, and much more. 
Snort has a real-time alerting capabilty, with alerts being sent to syslog, 
a seperate "alert" file, or as a WinPopup message via Samba's smbclient
Packager: Henri Gomez <gomez@slib.fr>, William Stearns <wstearns@pobox.com>, and Dave Wreski <dave@linuxsecurity.com>, Wim
Vandersmissen <wim@bofh.st>

%prep
%setup -q 

%build
autoconf
CFLAGS="$RPM_OPT_FLAGS" \
%configure --sysconfdir=/etc/snort --enable-smbalerts 
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_bindir},%{_mandir},%{_sbindir}}
install -d $RPM_BUILD_ROOT{%{_docdir},/etc/snort,var/log/snort/archive,/etc/rc.d/init.d}
make DESTDIR=$RPM_BUILD_ROOT prefix=/usr bindir=/usr/sbin sysconfdir=/etc/snort install
sed -e 's;include ;include /etc/snort/;' < snort-lib > snort-lib.new
rm -f snort-lib
mv snort-lib.new snort-lib
install *-lib $RPM_BUILD_ROOT/etc/snort
install %{SOURCE1} $RPM_BUILD_ROOT/usr/bin
install %{SOURCE2} $RPM_BUILD_ROOT/usr/bin
install %{SOURCE3} $RPM_BUILD_ROOT/usr/sbin
install %{SOURCE4} $RPM_BUILD_ROOT/etc/rc.d/init.d
install %{SOURCE5} $RPM_BUILD_ROOT/etc/snort
install %{SOURCE7} $RPM_BUILD_ROOT/etc/snort

%clean
rm -rf $RPM_BUILD_ROOT
						
%post
#don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
useradd -M -r -d /var/log/snort -s /bin/false -c "Snort" snort 2> /dev/null || true
groupadd -r snort 2> /dev/null || true
/sbin/chkconfig --add snortd
#this only works on redhat ;/
## -- that is ugly.. awk should be muuuch faster
perl -e 'open(f,"/etc/sysconfig/network-scripts/ifcfg-eth0");
         while(<f>){if  (/IPADDR=(.*)/) {$internal=$1;}};close(f);
         open(f,"/etc/resolv.conf");
         while(<f>){if (/nameserver(.*)/) {$dns=$1;$dns=~s/[ ]+//g;
         push(@dns,$dns);}} close(f);
         open(f,">/etc/snort/rules.base");
         print f "var INTERNAL $internal/32\nvar EXTERNAL any\nvar DNSSERVERS";
         foreach (@dns) {print f " $_/32";}
         print f "\n\npreprocessor http_decode: 80 443 8080\npreprocessor minfrag: 128\npreprocessor portscan: \$EXTERNAL 3 5 /var/log/snort/portscan.log\npreprocessor portscan-ignorehosts: \$DNSSERVERS\n\n";
         close(f);'
#add the rest of the stuff 
cat - << EOF >> /etc/snort/rules.base
# Ruleset, available (updated hourly) from:
#
#   http://dev.whitehats.com/ids/vision.rules

# Include the latest copy of Max Vision's ruleset
include /etc/snort/vision.rules

# Uncomment the next line if you wish to include the latest
# copy of the snort.org ruleset.  Be sure to download the latest
# one from http://www.snort.org/snort-files.htm#Rules
#
# include /etc/snort/07202k.rules

#
# If you wish to monitor multiple INTERNAL networks, you can include
# another variable that defines the additional network, then include
# the snort ruleset again.  Uncomment the two following lines.
#
# var INTERNAL 192.168.2.0/24
# include /etc/snort/vision.rules

# include other rules here if you wish.
EOF
fi

chown snort.snort /var/log/snort

echo -e "
Be sure to fetch the latest snort rules file from the ArachNIDS
database by Max Vision, or the one available from the snort.org web
site.

Included with this RPM is snort-update, a script written by 
Dave Dittrich that uses wget to regularly download the latest 
vision.rules file from dev.whitehats.com and alert you if it has 
been updated.  See the README.snort-stuff for info.

The snortlog and snort-stat perl scripts can be used to generate
statistics from the snort syslog entries.

Snort is currently configured to listen only on eth0, and assumes
the use of the ArachNIDS ruleset.  If this is not correct for your 
system, edit /etc/rc.d/init.d/snortd.

A \"snort\" user and group have been created for snort to run as instead
of running as root.  You will likely need to create the /var/log/snort 
directory, and change ownership to the \"snort\" account.

Built by: Dave Wreski
dave@linuxsecurity.com
and Wim Vandersmissen <wim@bofh.st>
"

%preun
/etc/rc.d/init.d/snortd stop
if [ $1 = 0 ] ; then
/sbin/chkconfig --del snortd
fi

%postun
#only if we are removing, not upgrading..
if [ $1 = 0 ] ; then
userdel snort 2> /dev/null || true
groupdel snort 2> /dev/null || true
fi

%files
%defattr(-,root,root)
%doc AUTHORS BUGS COPYING CREDITS ChangeLog INSTALL NEWS README* USAGE
%doc $RPM_SOURCE_DIR/README.snort-stuff
%attr(755,root,root)       /usr/sbin/*
%attr(755,root,root) 	   /usr/bin/*
#%attr(750,root,wheel)  %dir /var/log/snort
# cos mu nie pasuje..
#%attr(750,root,wheel)  %dir /var/log/snort/archive
%attr(640,root,wheel) %config /etc/snort/*-lib
%attr(640,root,wheel) %config /etc/snort/vision.rules
%attr(640,root,wheel) %config(noreplace)     /etc/snort/rules.base
%attr(750,root,root)   /etc/rc.d/init.d/snortd

%changelog
* Fri Nov  3 2000 agaran
- i changed some..

* Tue Jul 25 2000 Wim Vandersmissen <wim@bofh.st>
- Added some checks to find out if we're upgrading or removing the package

* Sat Jul 22 2000 Wim Vandersmissen <wim@bofh.st>
- Updated to version 1.6.3
- Fixed the user/group stuff (moved to %post)
- Added userdel/groupdel to %postun
- Automagically adds the right IP, nameservers to /etc/snort/rules.base

* Sat Jul 08 2000 Dave Wreski <dave@linuxsecurity.com>
- Updated to version 1.6.2
- Removed references to xntpd
- Fixed minor problems with snortd init script

* Fri Jul 07 2000 Dave Wreski <dave@linuxsecurity.com>
- Updated to version 1.6.1
- Added user/group snort

* Sat Jun 10 2000 Dave Wreski <dave@linuxsecurity.com>
- Added snort init.d script (snortd)
- Added Dave Dittrich's snort rules header file (ruiles.base)
- Added Dave Dittrich's wget rules fetch script (check-snort)
- Fixed permissions on /var/log/snort
- Created /var/log/snort/archive for archival of snort logs
- Added post/preun to add/remove snortd to/from rc?.d directories
- Defined configuration files as %config

* Tue Mar 28 2000 William Stearns <wstearns@pobox.com>
- Quick update to 1.6.
- Sanity checks before doing rm-rf in install and clean

* Fri Dec 10 1999 Henri Gomez <gomez@slib.fr>
- 1.5-0 Initial RPM release
