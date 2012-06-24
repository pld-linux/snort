#
# Conditional build:
# _without_pgsql	build without PostgreSQL support
# _without_mysql	build without MySQL support
# _without_snmp		without SNMP support
#
Summary:	Network intrusion detection system
Summary(pl):	System wykrywania intruz�w w sieciach
Summary(pt_BR):	Ferramenta de detec��o de intrusos
Summary(ru):	Snort - ������� ����������� ������� ��������� � ����
Summary(uk):	Snort - ������� ��������� ����� ���������� � ������
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
