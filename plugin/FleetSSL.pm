package Cpanel::API::FleetSSL;

# Exposes the FleetSSL JSON API (served by letsencrypt.live.cgi) to cPanel
# UAPI. Each function here is a thin shim: it translates UAPI arguments into
# a CGI-style request, invokes the existing Go CGI binary, and translates
# the JSON response back into UAPI's $result object.
#
# UAPI examples (shell):
#   uapi FleetSSL list_certificates
#   uapi FleetSSL issue_certificate virtual_host=example.com \
#       dns_identifiers=example.com,www.example.com \
#       challenge_method=http-01
#
# UAPI examples (HTTP, authenticated cPanel session):
#   GET  /execute/FleetSSL/list_certificates
#   POST /execute/FleetSSL/issue_certificate

use strict;
use warnings;

use bytes       ();
use IO::Select  ();
use IPC::Open3  ();
use POSIX       ();
use Symbol      ();
use Cpanel       ();
use Cpanel::JSON ();
use Cpanel::AdminBin::Call ();

our $VERSION = '1.0';

our $CGI_BINARY = '/opt/fleetssl-cpanel/letsencrypt.live.cgi';

our %API = (
    _needs_feature           => 'letsencrypt-cpanel',
    list_certificates        => { allow_demo => 0 },
    issue_certificate        => { allow_demo => 0 },
    remove_certificate       => { allow_demo => 0 },
    reinstall_certificate    => { allow_demo => 0 },
    reuse_certificate        => { allow_demo => 0 },
    remove_certificate_reuse => { allow_demo => 0 },
);

sub list_certificates {
    my ( $args, $result ) = @_;
    return _invoke( 'list-certificates', 'GET', undef, $result );
}

sub issue_certificate {
    my ( $args, $result ) = @_;

    my $vhost = $args->get_length_required('virtual_host');
    my @dns   = _get_list( $args, 'dns_identifiers' );
    my $cm    = $args->get_length_required('challenge_method');

    if ( !@dns ) {
        $result->raw_error('`dns_identifiers` must include at least one DNS name');
        return 0;
    }

    my $body = {
        virtual_host        => $vhost,
        dns_identifiers     => \@dns,
        challenge_method    => $cm,
        preferred_issuer_cn => scalar( $args->get('preferred_issuer_cn') // '' ),
        dry_run             => $args->get('dry_run') ? Cpanel::JSON::true() : Cpanel::JSON::false(),
        key_type            => scalar( $args->get('key_type') // '' ),
    };

    return _invoke( 'issue-certificate', 'POST', $body, $result );
}

sub remove_certificate {
    my ( $args, $result ) = @_;
    my $body = { virtual_host => scalar $args->get_length_required('virtual_host') };
    return _invoke( 'remove-certificate', 'POST', $body, $result );
}

sub reinstall_certificate {
    my ( $args, $result ) = @_;
    my $body = {
        virtual_host     => scalar $args->get_length_required('virtual_host'),
        preferred_issuer => scalar( $args->get('preferred_issuer') // '' ),
    };
    return _invoke( 'reinstall-certificate', 'POST', $body, $result );
}

sub reuse_certificate {
    my ( $args, $result ) = @_;
    my $body = {
        dest_virtual_host => scalar $args->get_length_required('dest_virtual_host'),
        src_virtual_host  => scalar $args->get_length_required('src_virtual_host'),
    };
    return _invoke( 'reuse-certificate', 'POST', $body, $result );
}

sub remove_certificate_reuse {
    my ( $args, $result ) = @_;
    my $body = { dest_virtual_host => scalar $args->get_length_required('dest_virtual_host') };
    return _invoke( 'remove-certificate-reuse', 'POST', $body, $result );
}

# Fetches a list-valued argument. Supports both "name=a,b,c" and the
# UAPI-standard indexed form "name-0=a name-1=b". Empty entries are stripped.
sub _get_list {
    my ( $args, $name ) = @_;

    my @out;
    # Indexed form: name-0, name-1, ...
    for my $i ( 0 .. 1023 ) {
        my $v = $args->get("$name-$i");
        last if !defined $v;
        push @out, $v if length $v;
    }

    if ( !@out ) {
        my $joined = $args->get($name);
        if ( defined $joined && length $joined ) {
            @out = grep { length } split /\s*,\s*/, $joined;
        }
    }

    return @out;
}

sub _invoke {
    my ( $function, $method, $body_ref, $result ) = @_;

    if ( !$ENV{CPANEL_CONNECT_SOCKET} ) {
        return _invoke_cli( $function, $body_ref, $result );
    }

    my $body_json = defined($body_ref) ? Cpanel::JSON::Dump($body_ref) : '';

    local %ENV = %ENV;
    $ENV{REQUEST_METHOD}    = $method;
    $ENV{QUERY_STRING}      = "api_function=$function&api_version=1";
    $ENV{CONTENT_TYPE}      = 'application/json';
    $ENV{CONTENT_LENGTH}    = bytes::length($body_json);
    $ENV{HTTP_ACCEPT}       = 'application/json';
    $ENV{SCRIPT_NAME}       = '/letsencrypt/letsencrypt.live.cgi';
    $ENV{GATEWAY_INTERFACE} = 'CGI/1.1';
    $ENV{SERVER_PROTOCOL}   = 'HTTP/1.1';

    my ( $cgi_in, $cgi_out );
    my $cgi_err = Symbol::gensym();

    my $pid = eval { IPC::Open3::open3( $cgi_in, $cgi_out, $cgi_err, $CGI_BINARY ) };
    if ( !$pid || $@ ) {
        $result->raw_error( "Failed to invoke FleetSSL CGI ($CGI_BINARY): " . ( $@ || $! ) );
        return 0;
    }

    if ( length $body_json ) {
        print {$cgi_in} $body_json;
    }
    close $cgi_in;

    # Drain stdout and stderr concurrently. Reading one fully before the other
    # can deadlock IPC::Open3 if the child fills the un-read pipe's buffer.
    my ( $stdout, $stderr ) = ( '', '' );
    my $sel = IO::Select->new( $cgi_out, $cgi_err );
    while ( my @ready = $sel->can_read ) {
        for my $fh (@ready) {
            my $buf = '';
            my $n   = sysread( $fh, $buf, 65536 );
            if ( !defined $n || $n == 0 ) {
                $sel->remove($fh);
                close $fh;
                next;
            }
            if ( $fh == $cgi_out ) { $stdout .= $buf }
            else                   { $stderr .= $buf }
        }
    }

    waitpid $pid, 0;
    my $status = $? >> 8;

    # The Go net/http/cgi handler emits CGI headers (e.g. "Status: 200 OK\r\n
    # Content-Type: application/json\r\n\r\n{...}"). Strip them before parsing.
    my $payload = $stdout // '';
    if ( $payload =~ /\r?\n\r?\n/ ) {
        ( undef, $payload ) = split /\r?\n\r?\n/, $payload, 2;
    }

    my $decoded = eval { Cpanel::JSON::Load($payload) };
    if ( $@ || ref($decoded) ne 'HASH' ) {
        my $snippet = substr( $payload // '', 0, 500 );
        $result->raw_error("Failed to parse FleetSSL CGI response (exit=$status): $snippet");
        return 0;
    }

    if ( !$decoded->{success} ) {
        my @errs = @{ $decoded->{errors} // [] };
        $result->raw_error( @errs ? join( '; ', @errs ) : "FleetSSL operation failed (exit=$status)" );
        return 0;
    }

    $result->data( $decoded->{data} );
    return 1;
}

sub _invoke_cli {
    my ( $function, $body_ref, $result ) = @_;

    my $body_json = defined($body_ref) ? Cpanel::JSON::Dump($body_ref) : '';

    my $output = eval {
        Cpanel::AdminBin::Call::call( 'FleetSSL', 'api', 'API_CALL', $function, $body_json );
    };
    if ($@) {
        $result->raw_error("FleetSSL admin call failed: $@");
        return 0;
    }

    my $decoded = ref($output) eq 'HASH' ? $output : eval { Cpanel::JSON::Load( $output // '' ) };
    if ( $@ || ref($decoded) ne 'HASH' ) {
        my $snippet = substr( $output // '', 0, 500 );
        $result->raw_error("Failed to parse FleetSSL CLI response: $snippet");
        return 0;
    }

    if ( !$decoded->{success} ) {
        my @errs = @{ $decoded->{errors} // [] };
        $result->raw_error( @errs ? join( '; ', @errs ) : 'FleetSSL operation failed' );
        return 0;
    }

    $result->data( $decoded->{data} );
    return 1;
}

1;
