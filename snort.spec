#
# Conditional build:
# _without_pgsql	build without PostgreSQL support
# _without_mysql	build without MySQL support
# _without_snmp		without SNMP support
#
Summary:	Network intrusion detection system
Summary(pl):	System wykrywania intruzСw w sieciach
Summary(pt_BR):	Ferramenta de detecГЦo de intrusos
Summary(ru):	Snort - система обнаружения попыток вторжения в сеть
Summary(uk):	Snort - система виявлення спроб вторгнення в мережу
Name:		snort
Version:	1.9.0
Release:	2
License:	GPL
Vendor:		Marty Roesch <roesch@sourcefire.com>
Group:		Networking
Source0:	http://www.snort.org/dl/%{name}-%{version}.tar.gz
# snort rules from: Sat Oct 26 14:15:30 2002 GMT
Source1:	http://www.snort.org/dl/signatures/%{name}rules-stable.tar.gz
Source2:	%{name}.init
Source3:	%{name}.logrotate
URL:		http://www.snort.org/
BuildRequires:	libnet-devel
BuildRequires:	libpcap-devel
%{!?_without_mysql:BuildRequires:	mysql-devel}
%{!?_without_pgsql:BuildRequires:	postgresql-devel}
BuildRequires:	openssl-devel >= 0.9.7
%{!?_without_snmp:BuildRequires:	net-snmp-devel >= 5.0.7}
BuildRequires:	zlib-devel
BuildRequires:	autoconf
BuildRequires:	automake
%{!?_without_mysql:Provides:	snort(mysql) = %{version}}
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
Snort to bazuj╠cy na open source NIDS (network intrusion detection
systems) wykonuj╠cy w czasie rzeczywistym analizЙ ruchu oraz logowanie
pakietСw w sieciach IP. Jego mo©liwo╤ci to analiza protokoЁu oraz
zawarto╤ci w poszukiwaniu rС©nego rodzaju atakСw lub prСb takich jak
przepeЁnienia bufora, skanowanie portСw typu stealth, ataki CGI,
prСbkowanie SMB, OS fingerprinting i du©o wiЙcej. Snort u©ywa
elastycznego jЙzyka reguЁek do opisu ruchu, ktСry nale©y
przeanalizowaФ jak rСwnie© silnika wykrywaj╠cego, wykorzystuj╠cego
moduЁow╠ architekturЙ. Snort umo©liwia alarmowanie w czasie
rzeczywistym poprzez sysloga, osobny plik lub jako wiadomo╤Ф WinPopup
poprzez klienta Samby: smbclient.

%description -l pt_BR
Snort И um sniffer baseado em libpcap que pode ser usado como um
pequeno sistema de detecГЦo de intrusos. Tem como caracterМstica o
registro de pacotes baseado em regras e tambИm pode executar uma
anАlise do protocolo, pesquisa de padrУes e detectar uma variedade de
assinaturas de ataques, como estouros de buffer, varreduras "stealth"
de portas, ataques CGI, pesquisas SMB, tentativas de descobrir o
sistema operacional e muito mais. Possui um sistema de alerta em tempo
real, com alertas enviados para o syslog, um arquivo de alertas em
separado ou como uma mensagem Winpopup.

%description -l ru
Snort - это сниффер пакетов, который может использоваться как система
обнаружения попыток вторжения в сеть. Snort поддерживает
протоколирование пакетов на основе правил, может выполнять анализ
протоколов, поиск в содержимом пакетов. Может также использоваться для
обнаружения атак и "разведок", таких как попытки атак типа
"переполнение буфера", скрытого сканирования портов, CGI атак, SMB
разведок, попыток обнаружения типа ОС и много другого. Snort может
информировать о событиях в реальном времени, посылая сообщения в
syslog, отдельный файл или как WinPopup сообщения через smbclient.

%description -l uk
Snort - це сн╕фер пакет╕в, що може використовуватись як система
виявлення спроб вторгнень в мережу. Snort п╕дтриму╓ протоколювання
пакет╕в на основ╕ правил, може виконувати анал╕з протокол╕в, пошук у
вм╕ст╕ пакет╕в. Може також використовуватись для виявлення атак та
"розв╕док", таких як спроби атак типу "переповнення буфера",
прихованого сканування порт╕в, CGI атак, SMB розв╕док, спроб виявлення
типу ОС та багато ╕ншого. Snort може ╕нформувати про под╕╖ в реальному
час╕, надсилаючи пов╕домлення до syslog, окремого файлу чи як WinPopup
пов╕домлення через smbclient.

%prep
%setup -q -a1

%build
rm -f missing
%{__aclocal}
%{__autoconf}
%{__automake}
%configure \
	--enable-smbalerts \
	--enable-flexresp \
	--with%{?_without_snmp:out}-snmp \
	--without-odbc \
	--with%{?_without_pgsql:out}-postgresql \
	--with%{?_without_mysql:out}-mysql

%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/{rc.d/init.d,%{name},cron.daily,logrotate.d} \
	$RPM_BUILD_ROOT%{_var}/log/{%{name},archiv/%{name}} \
	$RPM_BUILD_ROOT%{_datadir}/mibs/site

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install etc/*MIB*.txt	$RPM_BUILD_ROOT%{_datadir}/mibs/site
install etc/snort.conf	$RPM_BUILD_ROOT%{_sysconfdir}
install rules/*.{rules,config}		$RPM_BUILD_ROOT%{_sysconfdir}
install %{SOURCE2}	$RPM_BUILD_ROOT/etc/rc.d/init.d/%{name}
install %{SOURCE3}	$RPM_BUILD_ROOT/etc/logrotate.d/%{name}

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
%doc doc/{AUTHORS,BUGS,CREDITS,FAQ,NEWS,README*,RULES*,TODO,USAGE}
%doc contrib/create* doc/*.pdf
%attr(755,root,root)  %{_sbindir}/*
%attr(770,root,snort) %dir %{_var}/log/%{name}
%attr(770,root,snort) %dir %{_var}/log/archiv/%{name}
%attr(750,root,snort) %dir %{_sysconfdir}
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/*
%attr(754,root,root)  /etc/rc.d/init.d/%{name}
%attr(640,root,root)  /etc/logrotate.d/*
%{_datadir}/mibs/site/*.txt
%{_mandir}/man?/*
