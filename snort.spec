Summary:	packet-sniffer/logger
Summary(pl):	Sniffer oraz logger pakietów sieciowych
Name:		snort
Version:	1.7
Release:	3
License:	GPL
Vendor:		Marty Roesch <roesch@clark.net>
Group:		Networking
Group(de):	Netzwerkwesen
Group(pl):	Sieciowe
Source0:	http://www.snort.org/Files/%{name}-%{version}.tar.gz
Source1:	%{name}.init
Source2:	%{name}-rules.base
Source3:	%{name}-vision.rules
Source4:	%{name}-update
Source5:	%{name}.logrotate
URL:		http://www.snort.org/
BuildRequires:	libnet-devel
BuildRequires:	libpcap-devel
BuildRequires:	mysql-devel
BuildRequires:	openssl-devel >= 0.9.6a
BuildRequires:	sed
Prereq:		rc-scripts >= 0.2.0
Prereq:		%{_sbindir}/useradd
Prereq:		%{_sbindir}/groupadd
Prereq:		/sbin/chkconfig
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%define		_sysconfdir	/etc/snort
%define		_bindir		%{_sbindir}

%description
Snort is a libpcap-based packet sniffer/logger which can be used as a
lightweight network intrusion detection system. It features rules
based logging and can perform protocol analysis, content
searching/matching and can be used to detect a variety of attacks and
probes, such as buffer overflows, stealth port scans, CGI attacks, SMB
probes, OS fingerprinting attempts, and much more. Snort has a
real-time alerting capabilty, with alerts being sent to syslog, a
seperate "alert" file, or as a WinPopup message via Samba's smbclient.

%description -l pl
Snort to bazuj±cy na libpcapie sniffer/program loguj±cy, który mo¿e
byc u¿yty w systemach detekcji intruzów sieciowych. Jego mo¿liwo¶ci to
logowanie bazuj±ce na podstawie ustalonych regu³ oraz dodatkowe
analizy zawarto¶ci, wyszukiwanie/dopasowywanie, które umo¿liwia
wykrywcie ró¿nego rodzaju ataków takich jak przepe³nienia bufora,
skanowanie portów (stealth), ataki CGI, aktaki na SMB, pobieranie
,,odcisków palców'' (OS fingerprinting) i wiele wiêcej. Snort
umo¿liwia alarmowanie w czasie rzeczywistym poprzez sysloga, osobny
plik lub jako wiadomo¶æ WinPopup poprzez klienta Samby: smbclient.

%prep
%setup -q

%build
%configure \
	--enable-smbalerts \
	--enable-flexresp
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/{rc.d/init.d,%{name},cron.daily,logrotate.d} \
	$RPM_BUILD_ROOT%{_var}/log/{%{name},archiv/%{name}}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install *-lib		$RPM_BUILD_ROOT%{_sysconfdir}
install %{SOURCE2}	$RPM_BUILD_ROOT%{_sysconfdir}/rules.base
install %{SOURCE3}	$RPM_BUILD_ROOT%{_sysconfdir}/vision.rules
sed -e "s#include #include %{_sysconfdir}/%{name}/#g" \
	< snort.conf >	$RPM_BUILD_ROOT%{_sysconfdir}/snort.conf

install %{SOURCE1}	$RPM_BUILD_ROOT/etc/rc.d/init.d/%{name}
install %{SOURCE4}	$RPM_BUILD_ROOT/etc/cron.daily/%{name}
install %{SOURCE5}	$RPM_BUILD_ROOT/etc/logrotate.d/%{name}

gzip -9nf AUTHORS BUGS ChangeLog CREDITS NEWS README* RULES* USAGE

%clean
rm -rf $RPM_BUILD_ROOT

%pre
GID=46; %groupadd
UID=46; HOMEDIR=%{_var}/log/snort; COMMENT=SNORT; %useradd
	
%post
%chkconfig_add
if [ "$1" = "1" ] ; then
	touch %{_var}/log/%{name} && chown snort.snort %{_var}/log/%{name}
fi

%preun
%chkconfig_del

%postun
%userdel
%groupdel

%files
%defattr(644,root,root,755)
%doc *.gz contrib/create*
%attr(755,root,root)  %{_sbindir}/*
%attr(770,root,snort) %dir %{_var}/log/%{name}
%attr(770,root,snort) %dir %{_var}/log/archiv/%{name}
%attr(750,root,snort) %dir %{_sysconfdir}
%attr(640,root,snort) %config %{_sysconfdir}/*-lib
%attr(640,root,snort) %config %{_sysconfdir}/snort.conf
%attr(640,root,snort) %config %{_sysconfdir}/vision.rules
%attr(640,root,snort) %config(noreplace) %{_sysconfdir}/rules.base
%attr(754,root,root)  /etc/rc.d/init.d/%{name}
%attr(750,root,root)  /etc/cron.daily/*
%attr(640,root,root)  /etc/logrotate.d/*
%{_mandir}/man*/*
