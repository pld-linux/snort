#
# TODO: - snort rules - fix description
#
# Conditional build:
%bcond_without	pgsql	# build without PostgreSQL storage support
%bcond_without	mysql	# build without MySQL storage support
%bcond_without	snmp	# build without SNMP support
%bcond_without	inline	# build without inline support
%bcond_without	prelude	# build without prelude support
#
Summary:	Network intrusion detection system (IDS/IPS)
Summary(pl):	System wykrywania intruzСw w sieciach (IDS/IPS)
Summary(pt_BR):	Ferramenta de detecГЦo de intrusos
Summary(ru):	Snort - система обнаружения попыток вторжения в сеть
Summary(uk):	Snort - система виявлення спроб вторгнення в мережу
Name:		snort
Version:	2.4.4
Release:	1
License:	GPL v2
Group:		Networking
Source0:	http://www.snort.org/dl/current/%{name}-%{version}.tar.gz
# Source0-md5:	9dc9060d1f2e248663eceffadfc45e7e
Source1:	http://www.snort.org/pub-bin/downloads.cgi/Download/vrt_pr/%{name}rules-pr-2.4.tar.gz
# Source1-md5:	35d9a2486f8c0280bb493aa03c011927
Source2:	%{name}.init
Source3:	%{name}.logrotate
Source4:	%{name}.conf
Patch0:		%{name}-libnet1.patch
Patch1:		%{name}-lib64.patch
URL:		http://www.snort.org/
BuildRequires:	autoconf
BuildRequires:	automake
%{?with_inline:BuildRequires:	iptables-devel}
BuildRequires:	libnet1-devel = 1.0.2a
BuildRequires:	libpcap-devel
%{?with_prelude:BuildRequires:	libprelude-devel}
%{?with_mysql:BuildRequires:	mysql-devel}
%{?with_snmp:BuildRequires:	net-snmp-devel >= 5.0.7}
BuildRequires:	openssl-devel >= 0.9.7d
BuildRequires:	pcre-devel
%{?with_pgsql:BuildRequires:	postgresql-devel}
BuildRequires:	rpmbuild(macros) >= 1.202
BuildRequires:	rpmbuild(macros) >= 1.268
BuildRequires:	zlib-devel
Requires(post,preun):	/sbin/chkconfig
Requires(postun):	/usr/sbin/groupdel
Requires(postun):	/usr/sbin/userdel
Requires(pre):	/bin/id
Requires(pre):	/usr/bin/getgid
Requires(pre):	/usr/sbin/groupadd
Requires(pre):	/usr/sbin/useradd
Requires:	libnet1 = 1.0.2a
Requires:	rc-scripts >= 0.2.0
Provides:	group(snort)
%{?with_mysql:Provides:	snort(mysql) = %{version}}
%{?with_pgsql:Provides:	snort(pgsql) = %{version}}
Provides:	user(snort)
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

Sourcefire VRT Certified Rules requires registration.
https://www.snort.org/pub-bin/register.cgi

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

ReguЁy certyfikowane poprzez Sourcefire wymagaj╠ rejestracji.
https://www.snort.org/pub-bin/register.cgi

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

%package rules
Summary:	Snort rules
Summary(pl):	ReguЁki snorta
Group:		Networking
Requires:	%{name} = %{version}-%{release}

%description rules
Snort rules.

%description rules -l pl
ReguЁki snorta.

%prep
%setup -q -a1
%patch0 -p1
%if "%{_lib}" == "lib64"
%patch1 -p1
%endif

%build
%{__aclocal}
%{__autoconf}
%{__automake}
# we don't need libnsl, so don't use it
%configure \
	no_libnsl=yes \
	--enable-smbalerts \
	--enable-flexresp \
	%{?with_inline:--enable-inline } \
	%{?with_inline:--with-libipq-includes=%{_includedir}/libipq }  \
	--with-libnet-includes=%{_includedir} \
	--with%{!?with_snmp:out}-snmp \
	--without-odbc \
	--enable-perfmonitor \
	--with%{!?with_pgsql:out}-postgresql \
	--with%{!?with_mysql:out}-mysql \
	%{?with_prelude:--enable-prelude }

%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/{rc.d/init.d,%{name},cron.daily,logrotate.d} \
	$RPM_BUILD_ROOT%{_var}/log/{%{name},archiv/%{name}} \
	$RPM_BUILD_ROOT%{_datadir}/mibs/site \
	$RPM_BUILD_ROOT%{_sysconfdir}/rules

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install rules/*.config	$RPM_BUILD_ROOT%{_sysconfdir}
install etc/unicode.map	$RPM_BUILD_ROOT%{_sysconfdir}
install rules/*.rules	$RPM_BUILD_ROOT%{_sysconfdir}/rules
install %{SOURCE2}	$RPM_BUILD_ROOT/etc/rc.d/init.d/%{name}
install %{SOURCE3}	$RPM_BUILD_ROOT/etc/logrotate.d/%{name}
install %{SOURCE4}	$RPM_BUILD_ROOT%{_sysconfdir}

mv schemas/create_mysql schemas/create_mysql.sql
mv schemas/create_postgresql schemas/create_postgresql.sql

%clean
rm -rf $RPM_BUILD_ROOT

%pre
%groupadd -g 46 -r snort
%useradd -u 46 -g snort -M -r -d %{_var}/log/snort -s /bin/false -c "SNORT IDS/IPS" snort

%post
/sbin/chkconfig --add snort
%service snort restart
if [ "$1" = 1 ]; then
	%banner -e %{name} <<-EOF
	To run snort you must download and install snort rules.
	poldek -u snort-rules or download from http://www.snort.org/
EOF
fi


%preun
if [ "$1" = "0" ] ; then
	%service snort stop
	/sbin/chkconfig --del snort
fi

%postun
if [ "$1" = "0" ] ; then
	%userremove snort
	%groupremove snort
fi

%files
%defattr(644,root,root,755)
%doc doc/{AUTHORS,BUGS,CREDITS,NEWS,PROBLEMS,README*,RULES.todo,TODO,USAGE,WISHLIST,*.pdf}
%doc schemas/create_{mysql,postgresql}.sql
%attr(755,root,root) %{_sbindir}/*
%attr(770,root,snort) %dir %{_var}/log/snort
%attr(770,root,snort) %dir %{_var}/log/archiv/%{name}
%attr(750,root,snort) %dir %{_sysconfdir}
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/unicode.map
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/*.config
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/snort.conf
%attr(750,root,snort) %dir %{_sysconfdir}/rules
%attr(754,root,root) /etc/rc.d/init.d/%{name}
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/logrotate.d/*
%{_mandir}/man?/*

%files rules
%defattr(644,root,root,755)
%attr(640,root,snort) %{_sysconfdir}/rules/*
