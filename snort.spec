Summary: packet-sniffer/logger
Name: snort
Version: 1.5
Release: 0
Copyright: GPL
Group: Applications/Internet
Source0: http://www.clark.net/~roesch/%{name}-%{version}.tar.gz
Source1: snort-stat
Source2: snortlog
Url: http://www.clark.net/~roesch/security.html
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)
Prefix: /usr
Packager: Henri Gomez <gomez@slib.fr>
Requires: libpcap >= 0.4
BuildRequires: libpcap >= 0.4

%description
Snort is a libpcap-based packet sniffer/logger which 
can be used as a lightweight network intrusion detection system. 
It features rules based logging and can perform protocol analysis, 
content searching/matching and can be used to detect a variety of 
attacks and probes, such as buffer overflows, stealth port scans, 
CGI attacks, SMB probes, OS fingerprinting attempts, and much more. 
Snort has a real-time alerting capabilty, with alerts being sent to syslog, 
a seperate "alert" file, or as a WinPopup message via Samba's smbclient

%prep
%setup -q 

%build
CFLAGS="$RPM_OPT_FLAGS" \
./configure --prefix=/usr --bindir=/usr/sbin --sysconfdir=/etc/snort --enable-smbalerts
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/etc/snort
mkdir -p $RPM_BUILD_ROOT/var/log/snort
make prefix=$RPM_BUILD_ROOT/usr bindir=$RPM_BUILD_ROOT/usr/sbin sysconfdir=$RPM_BUILD_ROOT/etc/snort install
sed -e 's;include ;include /etc/snort/;' < snort-lib > snort-lib.new
rm -f snort-lib
mv snort-lib.new snort-lib
install *-lib $RPM_BUILD_ROOT/etc/snort 
install %{SOURCE1} %{SOURCE2} $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/doc

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(644,root,root)       /etc/snort/*
%attr(755,root,root)       /usr/sbin/*
%attr(755,root,root) 	   /usr/bin/*
%attr(755,root,root)  %dir /var/log/snort
%doc AUTHORS BUGS COPYING CREDITS ChangeLog INSTALL NEWS README* USAGE

%changelog
* Fri Dec 10 1999 Henri Gomez <gomez@slib.fr>
- 1.5-0
  Initial RPM release
