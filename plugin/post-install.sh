#!/usr/bin/env bash

chmod +x /opt/fleetssl-cpanel/get_proxy_names

cd /opt/fleetssl-cpanel && ./letsencrypt.live.cgi -mode install

# symlink for easy access
ln -sf /opt/fleetssl-cpanel/letsencrypt.live.cgi /usr/local/bin/le-cp

# we need to restart apache to load in the new autossl exclusion urls the first time
NEEDS_APACHE_RESTART=0
if [ ! -e /var/cpanel/perl/Cpanel/SSL/Auto/Provider/FleetSSLProvider.pm ]; then
	echo "Will rebuild conf and restart Apache to reload AutoSSL DCV URLs"
	NEEDS_APACHE_RESTART=1
fi

# symlink autossl provider
mkdir -p /var/cpanel/perl/Cpanel/SSL/Auto/Provider/
ln -sf /opt/fleetssl-cpanel/FleetSSLProvider.pm /var/cpanel/perl/Cpanel/SSL/Auto/Provider/FleetSSLProvider.pm

# symlink UAPI module so endpoints are reachable via `uapi FleetSSL <fn>` and
# /execute/FleetSSL/<fn>. cPanel's Perl @INC includes /usr/local/cpanel but
# NOT /var/cpanel/perl, so the module has to live under the former.
mkdir -p /usr/local/cpanel/Cpanel/API
ln -sf /opt/fleetssl-cpanel/FleetSSL.pm /usr/local/cpanel/Cpanel/API/FleetSSL.pm
# Clean up the old (broken) path from 0.22.0 if a previous install left it behind.
rm -f /var/cpanel/perl/Cpanel/API/FleetSSL.pm

# AdminBin module for privilege escalation (UAPI runs as user, le-cp api needs root).
# Modern cPanel admin modules run inside cpsrvd as root — no external binary needed.
# Custom namespaces load from $CUSTOM_PERL_MODULES_DIR (/var/cpanel/perl/).
mkdir -p /var/cpanel/perl/Cpanel/Admin/Modules/FleetSSL
ln -sf /opt/fleetssl-cpanel/FleetSSL-adminbin.pm /var/cpanel/perl/Cpanel/Admin/Modules/FleetSSL/api.pm
mkdir -p /usr/local/cpanel/bin/admin/FleetSSL
ln -sf /opt/fleetssl-cpanel/FleetSSL-adminbin.conf /usr/local/cpanel/bin/admin/FleetSSL/api.conf

# rebuild httpconf to update new autossl provider and restart apache
if [ $NEEDS_APACHE_RESTART -eq "1" ]; then
	echo "Rebuilding Apache conf and restarting now ..."
	/scripts/rebuildhttpdconf && /scripts/restartsrv_httpd > /dev/null
fi

# Run installer script fix asynchronously so that we can automatically fix the prerm issue.
chmod +x /opt/fleetssl-cpanel/fix_fleetssl_cpanel_0.19.5-upgrade.sh
nohup /opt/fleetssl-cpanel/fix_fleetssl_cpanel_0.19.5-upgrade.sh 2>&1 >/dev/null &
