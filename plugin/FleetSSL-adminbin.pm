package Cpanel::Admin::Modules::FleetSSL::api;

use strict;
use warnings;

use parent qw( Cpanel::Admin::Base );

use constant _actions => qw(
    API_CALL
);

my %ALLOWED_FUNCTIONS = map { $_ => 1 } qw(
    list-certificates
    issue-certificate
    remove-certificate
    reinstall-certificate
    reuse-certificate
    remove-certificate-reuse
);

my $CGI_BINARY = '/opt/fleetssl-cpanel/letsencrypt.live.cgi';

sub API_CALL {
    my ( $self, $args ) = @_;

    my $function  = ref $args eq 'HASH' ? $args->{'function'} : $args;
    my $body_json = ref $args eq 'HASH' ? $args->{'body'}     : '';

    die "Invalid API function: $function\n"
        unless $function && $ALLOWED_FUNCTIONS{$function};

    my $user = $self->get_caller_username();
    die "Cannot determine calling user\n" unless $user;

    my @cmd = ( $CGI_BINARY, 'api', '--user', $user, '--function', $function );
    if ( defined $body_json && length $body_json ) {
        push @cmd, $body_json;
    }

    my $output = '';
    my $pid = open( my $fh, '-|', @cmd ) or die "Failed to exec $CGI_BINARY: $!\n";
    while (<$fh>) { $output .= $_ }
    close $fh;

    return $output;
}

1;
