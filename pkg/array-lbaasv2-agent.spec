%global pkg_name array-lbaasv2-agent

Name:           %{pkg_name}
Version:        1.0.0
Release:        1%{?dist}
Summary:        Array lbaas agent

License:        ASL 2.0
URL:            https://github.com/arraynetworks/array-lbaasv2-agent
Source0:        https://github.com/arraynetworks/array-lbaasv2-agent/%{pkg_name}.tar.gz
BuildArch:      noarch

%description
Array LBaaS v2 drivers for OpenStack.

%prep
%setup -q -n %{name}
# Let RPM handle the dependencies
rm -f requirements.txt

%build
%py2_build

%install

python setup.py install
%py2_install

%files -n %{pkg_name}
%doc README.rst
%license LICENSE
%{python2_sitelib}/array_lbaasv2_agent
%{python2_sitelib}/*.egg-info
/usr/bin/array-lbaasv2-agent
/usr/lib/systemd/system/array-lbaasv2-agent.service
/etc/neutron/conf.d/neutron-server/arraynetworks.conf

%changelog
* Thu Oct 25 2018 jarod.w <wangli2@arraynetworks.com.cn> 1.0.0-1
- Init the proj
