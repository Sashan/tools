use strict;
use warnings;
use File::Tempdir;
use IO::Pipe;
use File::Spec

my $OPENSSL_BINARIES;
my $TOOLS_PATH;
my $CERT_DIR;
my $OPENSSL_SRC;
my $TMPDIR;
my $RESULTS;
my @VERSIONS;
my @PERFTOOLS;
my @PERFTOOLS_NAME;
my $VERSIONS = ('1.1.1', '3.0', '3.3', 'master');
my @THREAD_COUNTS = (1, 2, 4, 8, 16, 32, 64, 128);
my $ITERATIONS = 25;
my $OUTPUT_FILE_NAME = $1;

my sub get_tool {
	my $TOOL_NAME = $1;
	my $TOOL = File::Spec->catfile($TOOLS_PATH, $TOOL_NAME);
	if (! -e $TOOL)
		return undef;
	else
		return $TOOL;
}

my sub evp_fetch {
	my $THREADS = $1;
	my $TOOL = get_tool('evp_fetch');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "EVP_FETCH_TYPE=MD:MD5 $TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub randbytes {
	my $THREADS = $1;
	my $TOOL = get_tool('randbytes');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub handshake {
	my $THREADS = $1;
	my $TOOL = get_tool('handshake');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS $CERT_DIR |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub sslnew {
	my $THREADS = $1;
	my $TOOL = get_tool('sslnew');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS $CERT_DIR |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub newrawkey {
	my $THREADS = $1;
	my $TOOL = get_tool('newrawkey');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub rsasign {
	my $THREADS = $1;
	my $TOOL = get_tool('rsasign');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub x509storeissuer {
	my $THREADS = $1;
	my $TOOL = get_tool('x509storeissuer');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub providerdoall {
	my $THREADS = $1;
	my $TOOL = get_tool('providerdoall');
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	$RESULT = $_;
	}
	close PIPE;

	return $RESULT;
}

my sub rwlocks_rlock {
	my $THREADS = $1;
	my $TOOL = get_tool('rwlocks');
	my @RESULT_ARRAY;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/ /, $_);
	}
	close PIPE;

	
	return @RESULT_ARRAY[0];
}

my sub rwlocks_wlock {
	my $THREADS = $1;
	my $TOOL = get_tool('rwlocks');
	my @RESULT_ARRAY;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/ /, $_);
	}
	close PIPE;

	return @RESULT_ARRAY[1];
}

my sub pkeyread_dh_der {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k dh -f der $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}

	return $RESULT;
}

my sub pkeyread_dhx_der {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k dhx -f der $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;


	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}

	return $RESULT;
}

my sub pkeyread_dsa_der {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k dsa -f der $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_ec_der {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k ec -f der $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_rsa_der {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k rsa -f der $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_x25519_der {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k x25519 -f der $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_dh_pem {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k dh -f pem $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_dhx_pem {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k dhx -f pem $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_dsa_pem {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k dsa -f pem $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_ec_pem {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k ec -f pem $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_rsa_pem {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k rsa -f pem $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

my sub pkeyread_x25519_pem {
	my $THREADS = $1;
	my $TOOL = get_tool('pkeyread');
	my @RESULT_ARRAY;
	my $RESULT;

	if (! $TOOL)
		return undef;

	open(PIPE, "$TOOL -t -k x25519 -f pem $THREADS |") || return undef;
	while (<PIPE>) {
		chomp;
        	@RESULT_ARRAY = split(/]/, $_);
	}
	close PIPE;

	if (@RESULT_ARRAY[1] =~ /(.*)(us)/) { 
		$RESULT = $1;
	} else {
		return undef;
	}


	return $RESULT;
}

@PERFTOOLS = (
	\&evp_fetch,
	\&randbytes,
	\&handshake,
	\&sslnew,
	\&newrawkey,
	\&rsasign,
	\&x509storeissuer,
	\&providerdoall,
	\&rwlocks_rlock,
	\&rwlocks_wlock,
	\&pkeyread_dh_der,
	\&pkeyread_dhx_der,
	\&pkeyread_dsa_der,
	\&pkeyread_ec_der,
	\&pkeyread_rsa_der,
	\&pkeyread_x25519_der,
	\&pkeyread_dh_pem,
	\&pkeyread_dhx_pem,
	\&pkeyread_dsa_pem,
	\&pkeyread_ec_pem,
	\&pkeyread_rsa_pem,
	\&pkeyread_x25519_pem
);

@PERFTOOLS_NAME = (
	'evp_fetch',
	'randbytes',
	'handshake',
	'sslnew',
	'newrawkey',
	'rsasign',
	'x509storeissuer',
	'providerdoall',
	'rwlocks_rlock',
	'rwlocks_wlock',
	'pkeyread_dh_der',
	'pkeyread_dhx_der',
	'pkeyread_dsa_der',
	'pkeyread_ec_der',
	'pkeyread_rsa_der',
	'pkeyread_x25519_der',
	'pkeyread_dh_pem',
	'pkeyread_dhx_pem',
	'pkeyread_dsa_pem',
	'pkeyread_ec_pem',
	'pkeyread_rsa_pem',
	'pkeyread_x25519_pem'
);

if (!$ENV{OPENSSL_BINARIES}) {
	print "OPENSSL_BINARIES is not set\n";
	exit 1;
}
$OPENSSL_BINARIES = $ENV{OPENSSL_BINARIES};
if (! -d $OPENSSL_BINARIES) {
	print "path OPENSSL_BINARIES($OPENSSL_BINARIES) does not exit\n";
	exit 1;
}
foreach(@VERSIONS) {
	my $LEAF_DIR = join('-', 'openssl', $_)
	my $OPENSSL_VERSION = File::Spec->catdir($OPENSSL_DIR, $LEAF_DIR);

	if (! -d $OPENSSL_VERSION) {
		print "No $LEAF_DIR found in $OPENSSL_DIR"
		exit 1;
	}
}

if (!$ENV{TOOLS_PATH}) {
	print "TOOLS_PATH is not set\n";
	exit 1;
}
$TOOLS_PATH=$ENV{TOOLS_PATH};
if (! -d $TOOLS_PATH) {
	print "path TOOLS_PATH($TOOLS_PATH) does not exit\n";
	exit 1;
}
foreach(@VERSIONS) {
	my $LEAF_DIR = join('-', 'build', $_)
	my $TOOL_VERSION = File::Spec->catdir($TOOLS_PATH, $LEAF_DIR);

	if (! -d $TOOL_VERSION) {
		print "No $LEAF_DIR found in $TOOLS_PATH"
		exit 1;
	}
}

if (!$ENV{OPENSSL_SRC}) {
	print "OPENSSL_SRC is not set\n";
	exit 1;
}
$OPENSSL_SRC=$ENV{OPENSSL_SRC};
if (! -d $OPENSSL_SRC) {
	print "path OPENSSL_SRC($OPENSSL_SRC) does not exit\n";
	exit 1;
}
$CERT_DIR = File::Spec->catfile($OPENSSL_SRC, 'test', 'certs');
if (! -d $CERT_DIR) {
	print "$OPENSSL_SRC does not contain test/certs";
	exit 1;
}

if (!$OUTPUT_FILE_NAME) {
	print "output file name argument is mandatory"
	exit 1
}
open(output_fh, ">", $OUTPUT_FILE_NAME) or die $!;

$TMPDIR = File::Tempdir->new();
$RESULTS = $TMPDIR->name

foreach(@VERSIONS) {
	my $VERSION = $_;

	foreach(@PERFTOOLS) {
		my $TOOL = $_;
		my $TOOL_INDEX = 0;

		foreach(@THREADS) {
			my $THREADS= $_;
			my $RESULT;
			my $FILE_NAME = join('.', @PERFTOOLS_NAME[$TOOL_INDEX], $VERSION);
			my $I;
			$FILE_NAME = join('-', $FILE_NAME, $THREADS);
			$FILE_NAME = File::Spec->catfile($RESULTS, $FILE_NAME);
			my $LD_LIBRARY_PATH = File::Spec->catdir($OPENSSL_DIR, join('-', 'openssl', $VERSION);
			my @RESULT_ARRAY;
			my @DEVIATION_ARRAY;
			my $SUM_DEVIATIONS = 0;
			my $AVG_USECS = 0;
			my $STD_DEVIATION=0;

			open(fh, ">", $FILE_NAME);
			if (!get_tool(@PERFTOOLS_NAME[$TOOL_INDEX])) {
				print fh ' N/A | N/A |'
				close(fh)
				continue;
			}

			for($I = 0; $I < $ITERATIONS; $I++) {
				print "Running: @PERFTOOLS_NAME[$TOOL_INDEX] $THREADS $ITERATIONS"
				push(@RESULT_ARRAY, $TOOL($THREADS));
			}

			foreach(@RESULT_ARRAY) {
				$AVG_USECS = $AVG_USECS + $_;
			}
			$AVG_USECS = $AVG_USECS / $ITERATIONS;

			foreach(@RESULT_ARRAY) {
				my $DEVIATION;
				$DEVIATION = $AVG_USECS - $_;
				$DEVIATION = $DEVIATION * $DEVIATION;
				push(@DEVIATION_ARRAY, $DEVIATION);
				$SUM_DEVIATIONS = $SUM_DEVIATIONS + $DEVIATION;
			}
			$STD_DEVIATION = sqrt($SUM_DEVIATIONS/($ITERATIONS - 1));
			print fh " $AVG_USECS | $STD_DEVIATION |";
			close fh;
		}
		$TOOL_INDEX++;
	}
}

foreach(@PERFTOOLS_NAME) {
	my $TOOL = $_;
	print output_fh "#### $TOOL\n\n";
	print output_fh "|thread_ count| number of iterations |";
	foreach(@VERSIONS) {
		my $VERSION = $_;
		print output_fh "openssl $VERSION per operation avg usec | $VERSION std dev |";
	}
	print OUTPUT_FH "\n";
	print OUTPUT_FH "|----|----";
	foreach(@VERSIONS) {
		print OUTPUT_FH "|----|----";
	}
	print output_fh "|\n";

	foreach(@THREADS) {
		print output_fh "| $_ | $ITERATIONS |"
		foreach(@VERSIONS) {
			my $FILE_NAME = join('-', $TOOL, $THREADS)
			my $RESULT;
			$FILE_NAME = File::Spec->catfile($RESULTS, $FILE_NAME);
			$RESULT = do {
				local $/ = undef;
				open(in_fh, "<", $FILE_NAME)
				<in_fh>
			};
			print output_fh $RESULT;
		}
		print output_fh "\n";
	}
	print output_fh "\n";
}

close output_fh;
