#
# Conditional build:
# _without_pgsql	build without PostgreSQL support
# _with_mysql		build MySQL support
# _without_snmp		without SNMP support
#
Summary:	Network intrusion detection system
Summary(pl):	System wykrywania intruzów w sieciach
Summary(pt_BR):	Ferramenta de detecção de intrusos
Name:		snort
Version:	1.8.3
Release:	1
License:	GPL
Vendor:		Marty Roesch <roesch@sourcefire.com>
Group:		Networking
Group(de):	Netzwerkwesen
Group(es):	Red
Group(pl):	Sieciowe
Group(pt_BR):	Rede
Source0:	http://www.snort.org/releases/%{name}-%{version}.tar.gz
Source1:	http://www.snort.org/downloads/%{name}rules.tar.gz
Source2:	%{name}.init
Source3:	%{name}.logrotate
URL:		http://www.snort.org/
BuildRequires:	libnet-devel
BuildRequires:	libpcap-devel
%{?_with_mysql:BuildRequires:	mysql-devel}
%{!?_without_pgsql:BuildRequires:	postgresql-devel}
BuildRequires:	openssl-devel >= 0.9.6a
%{!?_without_snmp:BuildRequires:	ucd-snmp-devel >= 4.2.2}
BuildRequires:	zlib-devel
BuildRequires:	autoconf
BuildRequires:	automake
%{?_with_mysql:Provides:	snort(mysql) = %{version}}
%{!?_without_pgsql:Provides:	snort(pgsql) = %{version}}
Prereq:		rc-scripts >= 0.2.0
Prereq:		/sbin/chkconfig
Prereq:		%{_sbindir}/useradd
Prereq:		%{_sbindir}/groupadd
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%define		_sysconfdir	/etc/snort
%define		_bindir		%{_sbindir}

%description
Snort is an open source network intrusion detection system, capable of
performing real-time traffic analysis and packet logging on IP
networks. It can perform protocol analysis and content
searching/matching in order to detect a variety of attacks and probes,
such as buffer overflows, stealth port scans, CGI attacks, SMB probes,
OS fingerprinting attempts, and much more. Snort uses a flexible rules
language to describe traffic that it should collect or pass, as well
as a detection engine that utilizes a modular plugin architecture.
Snort has a real- time alerting capability as well, incorporating
alerting mechanisms for syslog, user specified files, a UNIX socket,
or WinPopup messages to Windows clients using Samba's smbclient.

%description -l pl
Snort to bazuj±cy na open source NIDS (network intrusion detection
systems) wykonuj±cy w czasie rzeczywistym analizê ruchu oraz logowanie
pakietów w sieciach IP. Jego mo¿liwo¶ci to analiza protoko³u oraz
zawarto¶ci w poszukiwaniu ró¿nego rodzaju ataków lub prób takich jak
przepe³nienia bufora, skanowanie portów typu stealth, ataki CGI,
próbkowanie SMB, OS fingerprinting i du¿o wiêcej. Snort u¿ywa
elastycznego jêzyka regu³ek do opisu ruchu, który nale¿y
przeanalizowaæ jak równie¿ silnika wykrywaj±cego, wykorzystuj±cego
modu³ow± architekturê. Snort umo¿liwia alarmowanie w czasie
rzeczywistym poprzez sysloga, osobny plik lub jako wiadomo¶æ WinPopup
poprzez klienta Samby: smbclient.

%description -l pt_BR
Snort é um sniffer baseado em libpcap que pode ser usado como um
pequeno sistema de detecção de intrusos. Tem como característica o
registro de pacotes baseado em regras e também pode executar uma
análise do protocolo, pesquisa de padrões e detectar uma variedade de
assinaturas de ataques, como estouros de buffer, varreduras "stealth"
de portas, ataques CGI, pesquisas SMB, tentativas de descobrir o
sistema operacional e muito mais. Possui um sistema de alerta em tempo
real, com alertas enviados para o syslog, um arquivo de alertas em
separado ou como uma mensagem Winpopup.

%prep
%setup -q -a1

%build
rm -f missing
aclocal
autoconf
automake -a -c
%configure \
	--enable-smbalerts \
	--enable-flexresp \
	--with%{?_without_snmp:out}-snmp \
	--without-odbc \
	--with%{?_without_pgsql:out}-postgresql \
	--with%{!?_with_mysql:out}-mysql

%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/{rc.d/init.d,%{name},cron.daily,logrotate.d} \
	$RPM_BUILD_ROOT%{_var}/log/{%{name},archiv/%{name}} \
	$RPM_BUILD_ROOT%{_datadir}/mibs/site

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install MIBS/*.txt	$RPM_BUILD_ROOT%{_datadir}/mibs/site
install rules/*		$RPM_BUILD_ROOT%{_sysconfdir}
install %{SOURCE2}	$RPM_BUILD_ROOT/etc/rc.d/init.d/%{name}
install %{SOURCE3}	$RPM_BUILD_ROOT/etc/logrotate.d/%{name}

gzip -9nf AUTHORS BUGS ChangeLog CREDITS NEWS README* RULES* USAGE

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ -z "`getgid %{name}`" ]; then
	%{_sbindir}/groupadd -g 46 -r snort 2> /dev/null || true
fi

if [ -z "`id -u %{name} 2>/dev/null`" ]; then
	%{_sbindir}/useradd -u 46 -g %{name} -M -r -d %{_var}/log/%{name} -s /bin/false \
		-c "SNORT" snort 2> /dev/null || true
fi
	
%post
if [ "$1" = "1" ] ; then
	/sbin/chkconfig --add snort
	touch %{_var}/log/%{name} && chown snort.snort %{_var}/log/%{name}
fi

%preun
if [ "$1" = "0" ] ; then
	if [ -f /var/lock/subsys/snort ]; then
		/etc/rc.d/init.d/snort stop 1>&2
	fi
	/sbin/chkconfig --del snort
fi

%postun
if [ "$1" = "0" ] ; then
	%{_sbindir}/userdel snort 2> /dev/null || true
	%{_sbindir}/groupdel snort 2> /dev/null || true
fi

%files
%defattr(644,root,root,755)
%doc *.gz contrib/create* *.pdf
%attr(755,root,root)  %{_sbindir}/*
%attr(770,root,snort) %dir %{_var}/log/%{name}
%attr(770,root,snort) %dir %{_var}/log/archiv/%{name}
%attr(750,root,snort) %dir %{_sysconfdir}
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/*
%attr(754,root,root)  /etc/rc.d/init.d/%{name}
%attr(640,root,root)  /etc/logrotate.d/*
%{_datadir}/mibs/site/*.txt
%{_mandir}/man?/*
