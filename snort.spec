%define	plev	-patch2
Summary:	packet-sniffer/logger
Summary(pl):	Sniffer oraz logger pakietów sieciowych.
Name:		snort
Version:	1.6.3
Release:	1
License:	GPL
Group:		Networking
Group(de):	Netzwerkwesen
Group(pl):	Sieciowe
URL:		http://www.snort.org/
Vendor:		Marty Roesch <roesch@clark.net>
Source0:	http://www.snort.org/Files/%{name}-%{version}%{plev}.tar.gz
Source1:	%{name}.init
Source2:	%{name}-rules.base
Source3:	%{name}-vision.rules
Source4:	%{name}-update
Source5:	%{name}.logrotate
Patch0:		%{name}-configure.patch
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)
# shared libnet is broken
BuildRequires:	libnet-static
BuildRequires:	libpcap-devel
BuildRequires:	mysql-devel
BuildRequires:	sed
Requires:	rc-scripts >= 0.2.0
Prereq:		%{_sbindir}/useradd
Prereq:		%{_sbindir}/groupadd
Prereq:		/sbin/chkconfig

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
%setup -q -n %{name}-%{version}%{plev}
%patch0 -p1

%build
autoconf
automake
%configure \
	--sysconfdir=%{_sysconfdir}/snort \
	--bindir=%{_sbindir} \
	--enable-smbalerts \
	--enable-flexresp
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT%{_sysconfdir}/{rc.d/init.d,%{name},cron.daily,logrotate.d}
install -d $RPM_BUILD_ROOT%{_var}/log/{%{name},archiv/%{name}}

%{__make} \
	DESTDIR=$RPM_BUILD_ROOT \
	install

sed -e "s#include #include %{_sysconfdir}/%{name}/#g" \
	< snort-lib >	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/%{name}-lib
install *-lib		$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/

install %{SOURCE1}	$RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d/%{name}
install %{SOURCE2}	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/rules.base
install %{SOURCE3}	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/vision.rules
install %{SOURCE4}	$RPM_BUILD_ROOT%{_sysconfdir}/cron.daily/%{name}
install %{SOURCE4}	$RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/%{name}

gzip -9nf AUTHORS BUGS ChangeLog CREDITS NEWS README* RULES* USAGE

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ -z "`getgid %{name}`" ]; then
	%{_sbindir}/groupadd -g 46 -r snort 2> /dev/null || true
fi
if [ -z "`id -u %{name} 2>/dev/null`" ]; then
	%{_sbindir}/useradd -u 46 -M -r -d %{_var}/log/%{name} -s /bin/false \
		-c "SNORT" snort 2> /dev/null || true
fi
	
%post
if [ $1 = 1 ] ; then
	/sbin/chkconfig --add snort
	touch %{_var}/log/%{name} && chown snort.snort %{_var}/log/%{name}
fi

%preun
if [ $1 = 0 ] ; then
	if [ -f /var/lock/subsys/snort ]; then
		/etc/rc.d/init.d/snort stop 1>&2
	fi
	/sbin/chkconfig --del snort
fi

%postun
if [ $1 = 0 ] ; then
	%{_sbindir}/userdel snort 2> /dev/null || true
	%{_sbindir}/groupdel snort 2> /dev/null || true
fi

%files
%defattr(644,root,root,755)
%doc *.gz contrib/create*
%attr(755,root,root)  %{_sbindir}/*
%attr(770,root,snort) %dir %{_var}/log/%{name}
%attr(770,root,snort) %dir %{_var}/log/archiv/%{name}
%attr(750,root,snort) %dir %{_sysconfdir}/%{name}
%attr(640,root,snort) %config %{_sysconfdir}/%{name}/*-lib
%attr(640,root,snort) %config %{_sysconfdir}/%{name}/vision.rules
%attr(640,root,snort) %config(noreplace) %{_sysconfdir}/snort/rules.base
%attr(750,root,root)  %{_sysconfdir}/rc.d/init.d/%{name}
%attr(750,root,root)  %{_sysconfdir}/cron.daily/*
%attr(640,root,root)  %{_sysconfdir}/logrotate.d/*
%{_mandir}/man*/*
