#
# TODO: - snort rules - fix description
#	- clamav support - cleanup, add some docs
#	- snort_inline - prepare separate sets of config-files, rules
#	  and startup script, adds some docs
#	- snort 2.6
#
# Conditional build:
%bcond_without	pgsql	# build without PostgreSQL storage support
%bcond_without	mysql	# build without MySQL storage support
%bcond_without	snmp	# build without SNMP support
%bcond_without	inline	# build without inline support
%bcond_without	prelude	# build without prelude support
%bcond_without	clamav	# build w/o  ClamAV preprocessor support (anti-vir)
%bcond_with	registered	# build with rules available for registered users
#
Summary:	Network intrusion detection system (IDS/IPS)
Summary(pl.UTF-8):	System wykrywania intruzów w sieciach (IDS/IPS)
Summary(pt_BR.UTF-8):	Ferramenta de detecção de intrusos
Summary(ru.UTF-8):	Snort - система обнаружения попыток вторжения в сеть
Summary(uk.UTF-8):	Snort - система виявлення спроб вторгнення в мережу
Name:		snort
Version:	2.8.4.1
Release:	2
License:	GPL v2 (vrt rules on VRT-License)
Group:		Networking
Source0:	http://www.snort.org/dl/%{name}-%{version}.tar.gz
# Source0-md5:	63f4e76ae96a2d133f4c7b741bad5458
Source1:	http://www.snort.org/pub-bin/downloads.cgi/Download/vrt_pr/%{name}rules-pr-2.4.tar.gz
# Source1-md5:	35d9a2486f8c0280bb493aa03c011927
%if %{with registered}
Source2:	http://www.snort.org/pub-bin/downloads.cgi/Download/vrt_os/%{name}rules-snapshot-2.6.tar.gz
# NoSource2-md5:	0405ec828cf9ad85a03cbf670818f690
NoSource:	2
%endif
Source3:	http://www.snort.org/pub-bin/downloads.cgi/Download/comm_rules/Community-Rules-2.4.tar.gz
# Source3-md5:	f236b8a4ac12e99d3e7bd81bf3b5a482
Source4:	%{name}.init
Source5:	%{name}.logrotate
Patch0:		%{name}-libnet1.patch
Patch1:		%{name}-lib64.patch
URL:		http://www.snort.org/
BuildRequires:	autoconf
BuildRequires:	automake
%{?with_clamav:BuildRequires:	clamav-devel}
%{?with_inline:BuildRequires:	iptables-devel}
BuildRequires:	iptables-static
BuildRequires:	libnet-devel
BuildRequires:	libnet1-devel = 1.0.2a
BuildRequires:	libpcap-devel
%{?with_prelude:BuildRequires:	libprelude-devel}
BuildRequires:	libtool
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
Obsoletes:	snort-rules
Conflicts:	logrotate < 3.7-4
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

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

%description -l pl.UTF-8
Snort to bazujący na open source NIDS (network intrusion detection
systems) wykonujący w czasie rzeczywistym analizę ruchu oraz logowanie
pakietów w sieciach IP. Jego możliwości to analiza protokołu oraz
zawartości w poszukiwaniu różnego rodzaju ataków lub prób takich jak
przepełnienia bufora, skanowanie portów typu stealth, ataki CGI,
próbkowanie SMB, OS fingerprinting i dużo więcej. Snort używa
elastycznego języka regułek do opisu ruchu, który należy
przeanalizować jak również silnika wykrywającego, wykorzystującego
modułową architekturę. Snort umożliwia alarmowanie w czasie
rzeczywistym poprzez sysloga, osobny plik lub jako wiadomość WinPopup
poprzez klienta Samby: smbclient.

Reguły certyfikowane poprzez Sourcefire wymagają rejestracji.
https://www.snort.org/pub-bin/register.cgi

%description -l pt_BR.UTF-8
Snort é um sniffer baseado em libpcap que pode ser usado como um
pequeno sistema de detecção de intrusos. Tem como característica o
registro de pacotes baseado em regras e também pode executar uma
análise do protocolo, pesquisa de padrões e detectar uma variedade de
assinaturas de ataques, como estouros de buffer, varreduras "stealth"
de portas, ataques CGI, pesquisas SMB, tentativas de descobrir o
sistema operacional e muito mais. Possui um sistema de alerta em tempo
real, com alertas enviados para o syslog, um arquivo de alertas em
separado ou como uma mensagem Winpopup.

%description -l ru.UTF-8
Snort - это сниффер пакетов, который может использоваться как система
обнаружения попыток вторжения в сеть. Snort поддерживает
протоколирование пакетов на основе правил, может выполнять анализ
протоколов, поиск в содержимом пакетов. Может также использоваться для
обнаружения атак и "разведок", таких как попытки атак типа
"переполнение буфера", скрытого сканирования портов, CGI атак, SMB
разведок, попыток обнаружения типа ОС и много другого. Snort может
информировать о событиях в реальном времени, посылая сообщения в
syslog, отдельный файл или как WinPopup сообщения через smbclient.

%description -l uk.UTF-8
Snort - це сніфер пакетів, що може використовуватись як система
виявлення спроб вторгнень в мережу. Snort підтримує протоколювання
пакетів на основі правил, може виконувати аналіз протоколів, пошук у
вмісті пакетів. Може також використовуватись для виявлення атак та
"розвідок", таких як спроби атак типу "переповнення буфера",
прихованого сканування портів, CGI атак, SMB розвідок, спроб виявлення
типу ОС та багато іншого. Snort може інформувати про події в реальному
часі, надсилаючи повідомлення до syslog, окремого файлу чи як WinPopup
повідомлення через smbclient.

%prep
%setup -q %{!?with_registered:-a1} %{?with_registered:-a2} -a3
%patch0 -p1
%if "%{_lib}" == "lib64"
%patch1 -p1
%endif

sed -i "s#var\ RULE_PATH.*#var RULE_PATH /etc/snort/rules#g" rules/snort.conf
_DIR=$(pwd)
cd rules
for I in community-*.rules; do
	echo "include \$RULE_PATH/$I" >> snort.conf
done
cd $_DIR

%build
%{__libtoolize}
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
	%{?with_prelude:--enable-prelude } \
	%{?with_clamav:--enable-clamav --with-clamav-defdir=/var/lib/clamav}

%{__make} -j1

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT%{_initrddir} \
	$RPM_BUILD_ROOT%{_sysconfdir}/{%{name},cron.daily,logrotate.d} \
	$RPM_BUILD_ROOT%{_var}/log/{%{name},archive/%{name}} \
	$RPM_BUILD_ROOT%{_datadir}/mibs/site \
	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/rules

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT

install rules/*.config	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}
install etc/unicode.map	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}
install rules/*.rules	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}/rules
install %{SOURCE4}	$RPM_BUILD_ROOT%{_initrddir}/%{name}
install %{SOURCE5}	$RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/%{name}
install rules/snort.conf	$RPM_BUILD_ROOT%{_sysconfdir}/%{name}

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
%doc doc/{AUTHORS,BUGS,CREDITS,INSTALL,NEWS,PROBLEMS,README*,TODO,USAGE,WISHLIST,generators,*.pdf}
%doc schemas/create_{mysql,postgresql}.sql
%attr(755,root,root) %{_sbindir}/*
%attr(770,root,snort) %dir %{_var}/log/%{name}
%attr(770,root,snort) %dir %{_var}/log/archive/%{name}
%attr(750,root,snort) %dir %{_sysconfdir}/%{name}
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/unicode.map
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/*.config
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{name}/%{name}.conf
%attr(750,root,snort) %dir %{_sysconfdir}/%{name}/rules
%attr(640,root,snort) %{_sysconfdir}/%{name}/rules/*
%attr(754,root,root) %{_initrddir}/%{name}
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/logrotate.d/*
%{_mandir}/man?/*
%dir %{_libdir}/snort_dynamicengine
%dir %{_libdir}/snort_dynamicpreprocessor
%dir %{_libdir}/snort_dynamicrules
%attr(755,root,root) %{_libdir}/snort_dynamicengine/libsf_engine.so*
%attr(755,root,root) %{_libdir}/snort_dynamicpreprocessor/*.so*
%attr(755,root,root) %{_libdir}/snort_dynamicrules/lib_sfdynamic_example_rule.so*
