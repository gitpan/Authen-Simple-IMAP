package Authen::Simple::IMAP;

use warnings;
use strict;
use Carp;
use base 'Authen::Simple::Adapter';
use Data::Dumper;
use Params::Validate qw(validate_pos :types);

our $VERSION = '0.0.1';

__PACKAGE__->options({
	host => {
		type     => Params::Validate::SCALAR,
		optional => 1,
		depends  => [ 'protocol' ],
	},
	protocol => {
		type     => Params::Validate::SCALAR,
		default  => 'IMAP',
		optional => 1,
		depends  => [ 'host' ],
	},
	imap => {
		type     => Params::Validate::OBJECT,
		can		 => ['login','errstr'],
		optional => 1,
	},
	timeout => {
		type 	=> Params::Validate::SCALAR,
		optional => 1,
	},
	escape_slash => {
		type 	 => Params::Validate::SCALAR,
		optional => 1,
		default  => 1,
	},
});

sub init {
	my ($self, $args) = @_;
	if ( $args->{log} ) {
		$self->log($args->{log});
	}
	$self->log->debug("Starting init routine\n") if $self->log;
	#die Dumper($args)."\n";
	my @imap_args = ($args->{host});
	# need ALRM because Net::Simple::IMAP waits forever on getline 
	# and gmail, at least, accepts connection but supplies no line
	# on IMAP
	local( $SIG{ALRM} ) = sub { croak "timeout while connecting to server" };
	if ( defined($args->{timeout}) ) {
		push(@imap_args, timeout => $args->{timeout});
		alarm $args->{timeout};
	}
	else {
		alarm 90;
	}
	if ( defined($args->{imap}) ) {

		$self->log->info("setting up with user provided IMAP object ".
			ref($args->{imap})."\n") if $self->log;
	}
	elsif ( $args->{protocol} eq 'IMAPS' ) {
		local( $SIG{ALRM} ) = sub { croak "timeout while connecting to IMAPS server" };
		$self->log->info("setting up with IMAPS\n") if $self->log;
		require Net::IMAP::Simple::SSL;
		$args->{imap} = Net::IMAP::Simple::SSL->new(@imap_args) ||
			die "Unable to connect to IMAPS: $Net::IMAPS::Simple::errstr\n";
	}
	elsif ( $args->{protocol} eq 'IMAP' ) {
		local( $SIG{ALRM} ) = sub { croak "timeout while connecting to IMAP server" };
		$self->log->info("setting up with IMAP (no SSL)\n") if $self->log;
		require Net::IMAP::Simple;
		$args->{imap} = Net::IMAP::Simple->new(@imap_args) ||
			die "Unable to connect to IMAP: $Net::IMAP::Simple::errstr\n";
	}
	elsif ( defined($args->{protocol}) ) {
		croak "Valid protocols are 'IMAP' and 'IMAPS', not '".$args->{protocol}."'";
	}
	else { 
		croak "A protocol or an imap object is required";
	}
	alarm 0;
	return $self->SUPER::init($args);
}

sub check {
	my @params = validate_pos(@_,
		{
			type => OBJECT,
			isa  => 'Authen::Simple::IMAP',
		},
		{
			type => SCALAR,
		},
		{
			type => SCALAR,
		},
	);
	my ($self,$username,$password) = @params;
	$self->log->debug("Starting check routine\n") if $self->log;
	#$self->log->debug(Dumper($self->imap));
	
	if ( $self->escape_slash ) {
		$password =~ s[\\][\\\\]g;
	}

	if ( !defined($self->imap) ) {
		croak "THIS SHOULD NEVER HAPPEN: no IMAP object";
	}

	$self->log->info('Attempting to authenticate user \''.$username.'\''."\n") 
		if $self->log;
	if ( $self->imap->login($username,$password) ) {
		$self->log->info("Successfully logged in '".$username."'\n") 
			if $self->log;
		return 1;
	}
	#$self->log->info('Failed to authenticate user \''.$username.'\': '.$self->imap->errstr)."\n" if $self->log;
	return 0;
}

1; # Magic true value required at end of module
__END__

=head1 NAME

Authen::Simple::IMAP - Simple IMAP and IMAPS authentication

=head1 SYNOPSIS

    use Authen::Simple::IMAP;

    my $imap = Authen::Simple::IMAP->new(
        host => 'imap.example.com',
        protocol => 'IMAPS',
    );

    if ( $imap->authenticate( $username, $password ) ) {
           # successfull authentication
    }

     # or as a mod_perl Authen handler

     PerlModule Authen::Simple::Apache
     PerlModule Authen::Simple::IMAP

    PerlSetVar AuthenSimplePAM_host     "imap.example.com"
    PerlSetVar AuthenSimplePAM_protocol "IMAPS"

     <Location /protected>
         PerlAuthenHandler Authen::Simple::IMAP
         AuthType          Basic
         AuthName          "Protected Area"
         Require           valid-user
    </Location>

=head1 DESCRIPTION

Authenticate against IMAP or IMAPS services. 

Requires Net::IMAP::Simple for IMAP and Net::IMAP::Simple::SSL for IMAPS.
These modules are loaded when the object is created, not at compile time.

=head1 METHODS 

=over 4

=item  * new

This method takes a hash of parameters. The following options are
valid:

=over 8

=item * host

The hostname of the IMAP server

=item * protocol

Either 'IMAP' or 'IMAPS'.  Any other value causes an exception.
Selecting 'IMAPS' will cause an exception if Net::IMAP::Simple::SSL 
is not installed.

=item * log   

Any object that supports "debug", "info", "error" and "warn".

	log => Log::Log4perl->get_logger(’Authen::Simple::PAM’)

=item * escape_slash - DEFAULT TRUE

In my environment, a password will fail even if it is correct if it contains a
slash unless that slash is escaped with a preceeding slash.  I replace all
slashes with double-slashes in your password to keep this from being a problem.
I don't know if this is portable, a good idea or profoundly dangerously insane.
If you don't want this to behavior, set this value to false.  

=back

=item * authenticate( $username, $password ) 

Returns true on success and false on failure.

=back

=head1 DEPENDENCIES

Net::IMAP::Simple is required, and Net::IMAP::Simple::SSL is required for IMAPS.
Net::IMAP::Simple::Plus adds some patches to the otherwise abandoned and broken Net::IMAP::Simple, so I recommend it.   

=head1 BUGS AND LIMITATIONS

=over 4

=item *

I've never tried this in mod_perl, so including the mod_perl example in 
the synopsis is pure hubris on my part.

=item * 

This module uses Net::IMAP::Simple, which is broken and abandoned.  I should
either use something else or implement the IMAP stuff myself.  I wound up
wrapping the Net::IMAP::Simple stuff in an alarm+eval block to get it to behave.

=back

=head1 SEE ALSO

=over 4

=item Authen::Simple

=item Authen::Simple::Adapter

=item Net::IMAP::Simple

=item Net::IMAP::Simple::SSL

=back

=head1 CREDITS

=over 4

=item *

I pretty much ripped the best parts of this doc out of Christian Hansen's 
Authen::Simple::PAM and replaced "pam" with "imap" in a few places.  The 
lousy parts are my own.

=back

=head1 AUTHOR

Dylan Martin  C<< <dmartin@sccd.ctc.edu> >>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2009, Dylan Martin C<< <dmartin@sccd.ctc.edu> >> and Seattle
Central Community College.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
