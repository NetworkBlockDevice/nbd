use strict;

my $disk = "\0" x (1024*1024);

sub config_complete
{
}

sub open
{
    my $readonly = shift;
    my $h = { readonly => $readonly };
    return $h;
}

sub close
{
    my $h = shift;
}

sub get_size
{
    my $h = shift;
    return length ($disk);
}

sub can_write
{
    my $h = shift;
    return 1;
}

sub can_flush
{
    my $h = shift;
    return 1;
}

sub is_rotational
{
    my $h = shift;
    return 0;
}

sub can_trim
{
    my $h = shift;
    return 1;
}

sub pread
{
    my $h = shift;
    my $count = shift;
    my $offset = shift;
    return substr ($disk, $offset, $count);
}

sub pwrite
{
    my $h = shift;
    my $buf = shift;
    my $count = length ($buf);
    my $offset = shift;
    substr ($disk, $offset, $count) = $buf;
}

sub flush
{
    my $h = shift;
}

sub trim
{
    my $h = shift;
    my $count = shift;
    my $offset = shift;
}
