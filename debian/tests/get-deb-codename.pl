#!/usr/bin/perl -w

use v5.38;

$ENV{LC_ALL}="C";
open my $arch, '-|', 'dpkg --print-architecture';
my $runarch = <$arch>;
close $arch;
chomp $runarch;
open my $apt_policy, '-|', 'apt-cache policy';
my $curr = undef;
my $best = undef;

sub print_debug($data) {
	say STDERR $data if exists($ENV{POLICY_VERBOSE});
}

sub best($best, $curr) {
	return $best unless defined($curr);
	print_debug("curr defined: prio = " . $curr->{prio});
	return $best unless !exists($curr->{releaseopts}{a}) || $curr->{releaseopts}{a} ne "now";
	print_debug("not the now policy");
	return $best unless exists($curr->{releaseopts}{o}) && $curr->{releaseopts}{o} eq "Debian";
	print_debug("is debian");
	return $best unless exists($curr->{releaseopts}{c}) && $curr->{releaseopts}{c} eq "main";
	print_debug("is main");
	return $best unless $curr->{origin} ne "snapshot.debian.org";
	print_debug("is not snapshot");
	return $best unless !defined($best) || $best->{prio} >= $curr->{prio};
	print_debug("is highest priority");
	return $best unless $curr->{releaseopts}{b} eq $runarch;
	print_debug("is the correct arch");
	print_debug("checking that version " . ($curr->{releaseopts}{v} // "0") . " is larger than " . ($best->{releaseopts}{v} // "0"));
	return $best unless ($curr->{releaseopts}{v} // 0) > ($best->{releaseopts}{v} // 0);
	print_debug("has a higher version");
	return $curr;
}

while (<$apt_policy>) {
	if(/^\s*(?<prio>\d+)\s+(?<url>\S+).*$/) {
		$best = best($best, $curr);
		$curr = {};
		$curr->{prio} = $+{prio};
		$curr->{url} = $+{url};
	} elsif(/^\s+release\s+(?<releaseopts>.*)$/) {
		my $releaseopts = {};
		foreach my $release_opt(split /,/, $+{releaseopts}) {
			my ($opt_key, $opt_val) = split /=/, $release_opt;
			$releaseopts->{$opt_key} = $opt_val;
		}
		if(!exists($releaseopts->{v}) && exists($releaseopts->{a})) {
			if($releaseopts->{a} eq "unstable") {
				$releaseopts->{v} = 9999;
			} elsif(exists($releaseopts->{n}) && $releaseopts->{n} !~ /-debug/) {
				# probably testing
				$releaseopts->{v} = 9000;
			}
		}
		$curr->{releaseopts} = $releaseopts;
	} elsif(/^\s+origin\s+(?<origin>.*)$/) {
		$curr->{origin} = $+{origin};
	}
}
$best = best($best, $curr);

say $best->{releaseopts}{a};
close $apt_policy;
