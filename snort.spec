#
# Conditional build:
%bcond_without	pgsql	# build without PostgreSQL storage support
%bcond_without	mysql	# build without MySQL storage support
%bcond_without	snmp	# build without SNMP support
#
%define		_rules_ver	2_2
%define		_rc		RC1

Summary:	Network intrusion detection system
Summary(pl):	System wykrywania intruz�w w sieciach
Summary(pt_BR):	Ferramenta de detec��o de intrusos
Summary(ru):	Snort - ������� ����������� ������� ��������� � ����
Summary(uk):	Snort - ������� ��������� ����� ���������� � ������
Name:		snort
Version:	2.3.0
Release:	0.%{_rc}.1
License:	GPL
Vendor:		Marty Roesch <roesch@sourcefire.com>
Group:		Networking
Source0:	http://www.snort.org/dl/%{name}-%{version}%{_rc}.tar.gz
# Source0-md5:	c86ef4bd8f0e0eac102686a15f40ada8
Source1:	http://www.snort.org/dl/rules/snortrules-snapshot-%{_rules_ver}.tar.gz
# Source1-md5:	2e9947fb4bb2dc8ccdb6dc1e92832efb
Source2:	%{name}.init
Source3:	%{name}.logrotate
Source4:	%{name}.conf
Patch0:		%{name}-libnet1.patch
Patch1:		%{name}-lib64.patch
URL:		http://www.snort.org/
BuildRequires:	autoconf
BuildRequires:	automake
BuildRequires:	libnet1-devel = 1.0.2a
BuildRequires:	libpcap-devel
%{?with_mysql:BuildRequires:	mysql-devel}
%{?with_snmp:BuildRequires:	net-snmp-devel >= 5.0.7}
BuildRequires:	openssl-devel >= 0.9.7d
BuildRequires:	pcre-devel
%{?with_pgsql:BuildRequires:	postgresql-devel}
BuildRequires:	rpmbuild(macros) >= 1.159
BuildRequires:	zlib-devel
PreReq:		rc-scripts >= 0.2.0
Requires(pre):	/bin/id
Requires(pre):	/usr/bin/getgid
Requires(pre):	/usr/sbin/groupadd
Requires(pre):	/usr/sbin/useradd
Requires(post,preun):	/sbin/chkconfig
Requires(postun):	/usr/sbin/groupdel
Requires(postun):	/usr/sbin/userdel
Requires:	libnet1 = 1.0.2a
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

%description -l pl
Snort to bazuj�cy na open source NIDS (network intrusion detection
systems) wykonuj�cy w czasie rzeczywistym analiz� ruchu oraz logowanie
pakiet�w w sieciach IP. Jego mo�liwo�ci to analiza protoko�u oraz
zawarto�ci w poszukiwaniu r�nego rodzaju atak�w lub pr�b takich jak
przepe�nienia bufora, skanowanie port�w typu stealth, ataki CGI,
pr�bkowanie SMB, OS fingerprinting i du�o wi�cej. Snort u�ywa
elastycznego j�zyka regu�ek do opisu ruchu, kt�ry nale�y
przeanalizowa� jak r�wnie� silnika wykrywaj�cego, wykorzystuj�cego
modu�ow� architektur�. Snort umo�liwia alarmowanie w czasie
rzeczywistym poprzez sysloga, osobny plik lub jako wiadomo�� WinPopup
poprzez klienta Samby: smbclient.

%description -l pt_BR
Snort � um sniffer baseado em libpcap que pode ser usado como um
pequeno sistema de detec��o de intrusos. Tem como caracter�stica o
registro de pacotes baseado em regras e tamb�m pode executar uma
an�lise do protocolo, pesquisa de padr�es e detectar uma variedade de
assinaturas de ataques, como estouros de buffer, varreduras "stealth"
de portas, ataques CGI, pesquisas SMB, tentativas de descobrir o
sistema operacional e muito mais. Possui um sistema de alerta em tempo
real, com alertas enviados para o syslog, um arquivo de alertas em
separado ou como uma mensagem Winpopup.

%description -l ru
Snort - ��� ������� �������, ������� ����� �������������� ��� �������
����������� ������� ��������� � ����. Snort ������������
���������������� ������� �� ������ ������, ����� ��������� ������
����������, ����� � ���������� �������. ����� ����� �������������� ���
����������� ���� � "��������", ����� ��� ������� ���� ����
"������������ ������", �������� ������������ ������, CGI ����, SMB
��������, ������� ����������� ���� �� � ����� �������. Snort �����
������������� � �������� � �������� �������, ������� ��������� �
syslog, ��������� ���� ��� ��� WinPopup ��������� ����� smbclient.

%description -l uk
Snort - �� �Φ��� ����Ԧ�, �� ���� ����������������� �� �������
��������� ����� ��������� � ������. Snort Ц�����դ ��������������
����Ԧ� �� ����צ ������, ���� ���������� ���̦� �������̦�, ����� �
�ͦ�Ԧ ����Ԧ�. ���� ����� ����������������� ��� ��������� ���� ��
"���צ���", ����� �� ������ ���� ���� "������������ ������",
����������� ���������� ���Ԧ�, CGI ����, SMB ���צ���, ����� ���������
���� �� �� ������ ������. Snort ���� ����������� ��� ��Ħ� � ���������
��Ӧ, ���������� ��צ�������� �� syslog, �������� ����� �� �� WinPopup
��צ�������� ����� smbclient.

%prep
%setup -q -a1 -n %{name}-%{version}%{_rc}
%patch0 -p1
%if "%{_libdir}" == "%{_prefix}/lib64"
%patch1
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
	--with-libnet-includes=/usr/include/libnet1 \
	--with%{!?with_snmp:out}-snmp \
	--without-odbc \
	--with%{!?with_pgsql:out}-postgresql \
	--with%{!?with_mysql:out}-mysql

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

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ -n "`/usr/bin/getgid snort`" ]; then
	if [ "`/usr/bin/getgid snort`" != "46" ]; then
		echo "Error: group snort doesn't have gid=46. Correct this before installing %{name}." 1>&2
		exit 1
	fi
else
	/usr/sbin/groupadd -g 46 -r snort 1>&2
fi
if [ -n "`/bin/id -u snort 2>/dev/null`" ]; then
	if [ "`/bin/id -u snort`" != "46" ]; then
		echo "Error: user snort doesn't have uid=46. Correct this before installing %{name}." 1>&2
		exit 1
	fi
else
	/usr/sbin/useradd -u 46 -g snort -M -r -d %{_var}/log/snort \
		-s /bin/false -c "SNORT" snort 1>&2
fi

%post
if [ "$1" = "1" ] ; then
	/sbin/chkconfig --add snort
fi
if [ -f /var/lock/subsys/snort ]; then
	/etc/rc.d/init.d/snort restart 1>&2
else
	echo "Run \"/etc/rc.d/init.d/snort start\" to start Snort daemon."
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
	%userremove snort
	%groupremove snort
fi

%files
%defattr(644,root,root,755)
%doc doc/{AUTHORS,BUGS,CREDITS,FAQ,NEWS,README*,TODO,USAGE}
%doc contrib/create* doc/*.pdf
%attr(755,root,root) %{_sbindir}/*
%attr(770,root,snort) %dir %{_var}/log/snort
%attr(770,root,snort) %dir %{_var}/log/archiv/%{name}
%attr(750,root,snort) %dir %{_sysconfdir}
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/unicode.map
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/*.config
%attr(640,root,snort) %config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/snort.conf
%attr(750,root,snort) %dir %{_sysconfdir}/rules
%attr(640,root,snort) %{_sysconfdir}/rules/*
%attr(750,root,root) /etc/rc.d/init.d/%{name}
%attr(640,root,root) %config(noreplace) %verify(not md5 mtime size) /etc/logrotate.d/*
%{_mandir}/man?/*
