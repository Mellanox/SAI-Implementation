#!/usr/bin/perl

package utils;

use strict;
use warnings;
use diagnostics;
use Term::ANSIColor;

require Exporter;

our $NUMBER_REGEX = '(?:-?\d+|0x[A-F0-9]+)';

our $errors = 0;
our $warnings = 0;

our $HEADER_CONTENT = "";
our $SOURCE_CONTENT = "";
our $TEST_CONTENT = "";

sub WriteHeader
{
    my $content = shift;

    $HEADER_CONTENT .= $content . "\n";
}

sub WriteSource
{
    my $content = shift;

    $SOURCE_CONTENT .= $content . "\n";
}

sub WriteTest
{
    my $content = shift;

    $TEST_CONTENT .= $content . "\n";
}

sub WriteSectionComment
{
    my $content = shift;

    WriteHeader "\n/* $content */\n";
    WriteSource "\n/* $content */\n";
}

sub LogDebug
{
    print color('bright_blue') . "@_" . color('reset') . "\n" if $main::optionPrintDebug;
}

sub LogInfo
{
    print color('bright_green') . "@_" . color('reset') . "\n";
}

sub LogWarning
{
    $warnings++;
    print color('bright_yellow') . "WARNING: @_" . color('reset') . "\n";
}

sub LogError
{
    $errors++;
    print color('bright_red') . "ERROR: @_" . color('reset') . "\n";
}

sub WriteFile
{
    my ($file, $content) = @_;

    open (F, ">", $file) or die "$0: open $file $!";

    print F $content;

    close F;
}

sub GetHeaderFiles
{
    my $dir = shift;

    $dir = $main::INCLUDE_DIR if not defined $dir;

    opendir(my $dh, $dir) or die "Can't opendir $dir: $!";

    my @headers = grep { /^sai\w*\.h$/ and -f "$dir/$_" } readdir($dh);

    closedir $dh;

    return sort @headers;
}

sub GetMetaHeaderFiles
{
    return GetHeaderFiles(".");
}

sub ReadHeaderFile
{
    my $filename = shift;

    local $/ = undef;

    # first search file in meta directory

    $filename = "$main::INCLUDE_DIR/$filename" if not -e $filename;

    open FILE, $filename or die "Couldn't open file $filename: $!";

    binmode FILE;

    my $string = <FILE>;

    close FILE;

    return $string;
}

sub GetNonObjectIdStructNames
{
    my %structs;

    my @headers = GetHeaderFiles();

    for my $header (@headers)
    {
        my $data = ReadHeaderFile($header);

        # TODO there should be better way to extract those

        while ($data =~ /sai_(?:create|set)_\w+.+?\n.+const\s+(sai_(\w+)_t)/gim)
        {
            my $name = $1;
            my $rawname = $2;

            $structs{$name} = $rawname;

            if (not $name =~ /_entry_t$/)
            {
                LogError "non object id struct name '$name'; should end on _entry_t";
                next;
            }
        }
    }

    return sort values %structs;
}

sub GetStructLists
{
    my $data = ReadHeaderFile("$main::INCLUDE_DIR/saitypes.h");

    my %StructLists = ();

    my @lines = split/\n/,$data;

    for my $line (@lines)
    {
        next if not $line =~ /typedef\s+struct\s+_(sai_\w+_list_t)/;

        $StructLists{$1} = $1;
    }

    return %StructLists;
}

sub IsSpecialObject
{
    my $ot = shift;

    return ($ot eq "SAI_OBJECT_TYPE_FDB_FLUSH" or $ot eq "SAI_OBJECT_TYPE_HOSTIF_PACKET");
}

sub SanityCheckContent
{
    # since we generate so much metadata now
    # lets put some primitive sanity check
    # if everything we generated is fine

    my $testCount = @test::TESTNAMES;

    if ($testCount < 5)
    {
        LogError "there should be at least 5 test defined, got $testCount";
    }

    my $metaHeaderSize = 48832 * 0.99;
    my $metaSourceSize = 2216983 * 0.99;
    my $metaTestSize   = 104995 * 0.99;

    if (length($HEADER_CONTENT) < $metaHeaderSize)
    {
        LogError "generated saimetadata.h size is too small";
    }

    if (length($SOURCE_CONTENT) < $metaSourceSize)
    {
        LogError "generated saimetadata.c size is too small";
    }

    if (length($TEST_CONTENT) < $metaTestSize)
    {
        LogError "generated saimetadatatest.c size is too small";
    }
}

sub WriteMetaDataFiles
{
    SanityCheckContent();

    exit 1 if ($warnings > 0 or $errors > 0);

    WriteFile("saimetadata.h", $HEADER_CONTENT);
    WriteFile("saimetadata.c", $SOURCE_CONTENT);
    WriteFile("saimetadatatest.c", $TEST_CONTENT);
}

sub GetStructKeysInOrder
{
    my $structRef = shift;

    my @values = ();

    for my $key (keys %$structRef)
    {
        $values[$structRef->{$key}->{idx}] = $key;
    }

    return @values;
}

sub Trim
{
    my $value = shift;

    $value =~ s/\s+/ /g;
    $value =~ s/^\s*//;
    $value =~ s/\s*$//;

    return $value;
}

BEGIN
{
    our @ISA    = qw(Exporter);
    our @EXPORT = qw/
    LogDebug LogInfo LogWarning LogError
    WriteFile GetHeaderFiles GetMetaHeaderFiles ReadHeaderFile
    GetNonObjectIdStructNames IsSpecialObject GetStructLists GetStructKeysInOrder Trim
    WriteHeader WriteSource WriteTest WriteMetaDataFiles WriteSectionComment
    $errors $warnings $NUMBER_REGEX
    $HEADER_CONTENT $SOURCE_CONTENT $TEST_CONTENT
    /;
}

1;
