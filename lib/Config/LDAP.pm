package Config::LDAP;

use strict;
use 5.006;
use Carp;
use Parse::RecDescent;
#BEGIN { eval { require Data::Dumper; } }

our $VERSION = 0.01;

our %grammers;

###
### RFC 2252
###

$grammers{rfc2252} = { };

### remove lines beginning with `#'
$grammers{rfc2252} -> {pre} = sub {
    local($_) = $_[1]; 
    s{^#.*$}{}gm; 
};

### actual grammer (modified BNF)
$grammers{rfc2252} -> {grammer} = q{
    numericstring: /[0-9]+/

    keystring: /[a-zA-Z][-;a-zA-Z0-9]+/
    whsp     : /\s*/
    # dstring is really multi-character utf8, whenever we can get 
    # that typeglobbed (.?)
    dstring  : /[ -~]+/

    qdstring : whsp "'" dstring "'" whsp
    qdstringlist : qdstring(s)
                 |
    qdstrings: qdstring
             | whsp "(" qdstringlist ")" whsp

    oid      : descr
             | numericoid
    descr    : keystring
    numericoid: numericstring "." numericoid(s)
              { join(".", $item[1], @{$item[-1]}) }
              | numericstring
              { $item[1] }
    woid     : whsp oid whsp
             { $item[2] }
    oids     : woid
             | "(" oidlist ")"
             { [ split(/ \\$ /, $item[2]) ] }
    oidlist  : woid "\\$" oidlist(s)
             { join(' $ ', $item[1], @{$item[-1]}) }
             | woid
             { $item[1] }
    qdescrs  : qdescr
             { $item[1] }
             | whsp "(" qdescrlist ")" whsp
             { @{$item[3]} }
    qdescrlist: qdescr(s?)
             { @{$item}[1..-1] }
    qdescr   : whsp "'" descr "'" whsp
             { $item[3] }

    NAME : "NAME" qdescrs
         { $item[2] }
    DESC : "DESC" qdstring
         { $item[2] }
    OBSOLETE : "OBSOLETE" whsp
         { 1 }
    SUP : "SUP" woid
         { $item[2] }
    EQUALITY : "EQUALITY" woid
         { $item[2] }
    ORDERING : "ORDERING" woid
         { $item[2] }
    SUBSTR   : "SUBSTR" woid
         { $item[2] }
    SYNTAX   : "SYNTAX" whsp noidlen whsp
         { $item[3] }
    SINGLE_VALUE: "SINGLE-VALUE" whsp
         { 1 }
    COLLECTIVE: "COLLECTIVE" whsp
         { 1 }
    NO_USER_MODIFICATION: "NO-USER-MODIFICATION" whsp
         { 1 }
    USAGE    : "USAGE" whsp AttributeUsage
         { $item[3] }

    AttributeTypeDescription: "(" whsp numericoid whsp NAME(?) DESC(?) OBSOLETE(?) SUP(?) EQUALITY(?) ORDERING(?) SUBSTR(?) SYNTAX(?) SINGLE_VALUE(?) COLLECTIVE(?) NO_USER_MODIFICATION(?) USAGE(?) whsp ")"
				{ { "oid" => $item[3], 
                                    "name" => @{$item[5]} ? $item[5][0] || "" : "", 
                                    "desc" => $item[6] || "" ,
                                    "obsolete" => @{$item[7]} || "",
                                    "sup" => $item[8] || "",
                                    "equality" => @{$item[9]} || "",
                                    "ordering" => @{$item[10]} || "",
                                    "substr" => $item[11] || "",
                                    "syntax" => @{$item[12]} ? $item[12][0] || "" : "",
                                    "single-value" => @{$item[13]} || "",
                                    "collective" => @{$item[14]} || "",
                                    "no-user-modification" => @{$item[15]} || "",
                                    "usage" => $item[16] || "",
                                 } }
    AttributeUsage: "userApplications" | "directoryOperation" | "distributedOperation" | "dSAOperation"
    
    noidlen : numericoid "{" len "}"
            { "$item[1]:$item[3]" }
            | numericoid
            { $item[1] }

    len     : numericstring
            { $item[1] }

    OC_SUP  : "SUP" oids
    STRUCTURAL: "ABSTRACT" whsp
              { $item[1] => 1 }
              | "STRUCTURAL" whsp
              { $item[1] => 1 }
              | "AUXILIARY" whsp
              { $item[1] => 1 }
    MUST    : "MUST" oids
            { $item[2] }
    MAY     : "MAY"  oids
            { $item[2] }

    ObjectClassDescription : "(" whsp numericoid whsp NAME(?) DESC(?) OBSOLETE(?) OC_SUP(?) STRUCTURAL(?) MUST(?) MAY(?) whsp ")"
                           { { "oid" => $item[3],
                               "name" => @{$item[5]},
                               "desc" => $item[6],
                               "obsolete" => $item[7],
                               "sup" => $item[8],
                               #(ref $item[9] eq 'ARRAY' && @{$item[9]} && ($item[9][0] => $item[9][1])),
                               "must" => $item[10] && $item[10][0] || [ ],
                               "may" => $item[11] && $item[11][0] || [ ],
                            } }


    MRD_SYNTAX: "SYNTAX" numericoid

    #MatchingRuleDescription : "(" whsp numericoid whsp NAME(?) DESC(?) OBSOLETE(?) MRD_SYNTAX whsp ")"
    #MatchingRuleDescription : "(" numericoid NAME(?) DESC(?) OBSOLETE(?) MRD_SYNTAX ")"

    APPLIES : "APPLIES" oids
            { @{$item[2]} }

    #MatchingRuleUseDescription : "(" whsp numericoid whsp NAME(?) DESC(?) OBSOLETE(?) APPLIES whsp ")"
    MatchingRuleUseDescription : "(" numericoid NAME(?) DESC(?) OBSOLETE(?) APPLIES ")"

    OBJECT : "attributetype" whsp AttributeTypeDescription  whsp
             { $item[3]->{_type} = 'attributetype'; $item[3]; }
           | "objectclass" whsp ObjectClassDescription whsp
             { $item[3]->{_type} = 'objectclass'; $item[3]; }
           #| "matchingRule:" MatchingRuleDescription 
           #| "matchingRuleUse:" MatchingRuleUseDescription 

    Schema : OBJECT(s)
};

###
### OpenLDAP's SLAPD configuration format
###
### This is considered *highly* experimental at this time
### In fact, it's very *broken* right now
###
$grammers{slapd} = { };

### remove comments beginning with `#'
$grammers{slapd} -> {pre} = sub {
    local($_) = $_[1];
    s{^#.*$}{}gm;
    s{$}{;}gm;
    return $_;
};

### this is where we include any files identified by `include'
$grammers{slapd} -> {post} = sub {
    my($s, $a) = @_;
    my(@includes) = grep { $_ -> {_type} == 'include' && $_->{filename} } @{$a};
    $s->file($_->{filename}) || carp "Unable to include $$_{filename}: $!" 
        for @includes;
    #[ grep { $_ -> {_type} != 'include' } @{$a} ];
    $a;
};

### actual grammer
$grammers{slapd} -> {grammer} = q{
    string  : /[ -~]+/
    alphanumstring: /[a-zA-Z0-9]+/
    bool : /o(n|ff)/i
         | "yes" | "no" | "0" | "1"
    stop : /[;\n]/

    Attribute: alphanumstring alphanumstring(s) stop
            { #print "Defined attribute $item[1]\n";
              #print Data::Dumper -> Dump([$item[2]]); 
              { 'name' => $item[1],
                'syntax' => $item[2][-1],
                'short-forms' => @{$item[2]}[0..-2],
            } }

    ObjectClass: alphanumstring REQUIRES(?) ALLOWS(?) stop
               { { 'name' => $item[1],
                   'may'  => $item[3],
                   'must' => $item[2],
               } }

    REQUIRES: "requires" attributes
              { $item[2] }

    ALLOWS: "allows" attributes
              { $item[2] }

    attribute: alphanumstring
             { $item[1] }

    attributes: attribute "," attributes
             { [ $item[1], @{$item[2]} ] }
              | attribute
              { [ $item[1] ] }

    Include: string
           { { 'filename' => $item[1] } }

    Schemacheck: bool

    Referral: string

    Pidfile: string

    Argsfile: string

    Database: string

    Suffix: string

    RootDN: string

    RootPW: string

    Directory: string
    
    LINE: "include" Include ";"
        { $item[2] -> {_type} = 'include'; $item[2]; }
        | "schemacheck" Schemacheck ";"
        | "referral" Referral ";"
        | "pidfile" Pidfile ";"
        | "argsfile" Argsfile ";"
        | "database" Database ";"
        | "suffix" Suffix ";"
        | "rootdn" RootDN ";"
        | "rootpw" RootPW ";"
        | "directory" Directory ";"
        | "attribute" Attribute 
        { $item[2]->{_type} = 'attributetype'; $item[2]; }
        | "objectclass" ObjectClass 
        { $item[2]->{_type} = 'objectclass'; $item[2]; }
        | ";"
        { { } }

    Schema: LINE(s)
};

###                 ###
### END OF GRAMMERS ###
###                 ###

sub new {
    my $class = shift;
    my $self = bless { }, ref $class || $class;
    my %args = @_;
    my $type = $args{type} || [ keys %grammers ];

    $type = [ $type ] unless ref $type eq 'ARRAY';
    $self -> {_type} = $type;
    my $fn = $args{file} or return $self;
    $self -> file($fn);
    return $self;
}

sub file {
    my($self, $file) = @_;
    local($::RD_HINT) = 1;
    local($::RD_WARN) = 1;
    #local($::RD_TRACE) = 1;

    open my $fh, "<", $file or croak "Unable to open $file: $!";

    local($/) = "";

    my($text) = (<$fh>);

    close $fh;

    $self -> {_filename} = $file;

    my $schema;
    our %grammers;
    foreach my $g (@{$self -> {_type}}) {
        next unless $grammers{$g};
        my $t;
        if(defined $grammers{$g} -> {pre}) {
            $t = &{$grammers{$g} -> {pre}}($self, $text) 
        } else {
            $t = $text;
        }
        $grammers{$g} -> {compiled} ||= new Parse::RecDescent($grammers{$g}->{grammer});
        $schema = $grammers{$g} -> {compiled} -> Schema($t);
        $self->{_type} = $g, last if $schema;
    }
    return 0 unless $schema;
    $schema = &{$grammers{$self->{_type}} -> {post}}($self, $schema)
        if defined $grammers{$self->{_type}} -> {post};

    my $t;
    for my $i (@{$schema}) {
        $t = $i -> {_type} or next;
        delete $i -> {_type};
        $self -> {$t} -> {byoid} -> {$i -> {oid}} = $i;
        $self -> {$t} -> {byname} -> {lc $i -> {name}} = $i -> {oid} if $i -> {name};
        if(ref $i -> {'short-forms'} eq 'ARRAY') {
            $self -> {$t} -> {byname} -> {lc $_} = $i -> {oid} for @{$i->{'short-forms'}};
        }
    }

    return 1;
}

sub query_objectclass_oids { return keys %{$_[0] -> {objectclass} -> {byoid}}; }

sub query_attribute_oids { return keys %{$_[0] -> {attributetype} -> {byoid}}; }

sub query_objectclass_names { return keys %{$_[0] -> {objectclass} -> {byname}}; }

sub query_attribute_names { return keys %{$_[0] -> {attributetype} -> {byname}}; }

sub query_attribute {
    my($self, $woid) = @_;
    $woid = $self -> {attributetype} -> {byname} -> {$woid} 
        if $woid !~ m{^[0-9.]+$};

    return { %{$self -> {attributetype} -> {byoid} -> {$woid} || { }} };
}

sub query_objectclass {
    my($self, $woid) = @_;
    $woid = $self -> {objectclass} -> {byname} -> {$woid} 
        if $woid !~ m{^[0-9.]+$};  

    return { %{$self -> {objectclass} -> {byoid} -> {$woid} || { }} };
}

sub query_grammer { return $_[0] -> {_type}; }

__END__

=head1 NAME

Config::LDAP - Read LDAP attribute and object class configurations

=head1 SYNOPSIS

 use Config::LDAP;

 my $ldapc = new Config::LDAP(
         type => 'rfc2252',
     );

 $ldapc -> file('/usr/local/etc/openldap/slapd.oc.conf');
 $ldapc -> file('/usr/local/etc/openldap/slapd.at.conf');

 my @objectclasses = $ldapc -> query_objectclass_names();
 my @attributes    = $ldapc -> query_attribute_names();

=head1 DESCRIPTION

Config::LDAP is designed to read LDAP attribute and object class 
configuration files in several different formats by allowing for 
new grammers to be defined.

This module requires Parse::RecDescent.

=head1 METHODS

=over 4

=item new(%args)

This creates a new configuration object.  Valid arguments include 
C<file> and C<type>, though these are optional.

If C<file> is specified, the named file will be loaded.  If 
C<type> is specified (either a SCALAR or ARRAY REF), then the 
specified grammers will be tried in the order given.  Otherwise, 
all available grammers are tried.

=item file($filename)

This will load the file specified.  If a file has already been 
loaded or the type has been specified, then the file is expected 
to be of the same type.

Loading multiple files merges the content and does not replace 
information unless an object class or attribute type is redefined.
The later definition will replace the earlier definition.

=item query_objectclass_oids

This will return a list of oids representing the object classes 
defined by the configuration.

=item query_attribute_oids

This will return a list of oids representing the attribute types 
defined by the configuration.

=item query_objectclass_names

This will return a list of names representing the object classes 
defined by the configuration.  Object classes are not required to 
have names.

=item query_attribute_names

This will return a list of names representing the attribute types 
defined by the configuration.  Attribute types are not required 
to have names.

=item query_objectclass

This will return a hash with all the information available for 
the given object class.  The argument may be either an oid or a 
name.

=item query_attribute

This will return a hash with all the information available for 
the given attribute type.  The argument may be either an oid or a 
name.

=item query_grammer

This will return the name of the grammer that successfully parsed 
the configuration file.

=back 4

=head1 AVAILABLE GRAMMERS

The following grammers are defined in some fashion.  If no C<type> 
is specified before loading a file, all available grammers will 
be tried until one parses the file successfully.  Afterwards, all 
files being added to the configuration object will be expected to 
be in the same format.

=over 4

=item rfc2252

This format is defined in RFC 2252 -  Lightweight Directory Access 
Protocol (v3): Attribute Syntax Definitions.  The grammer only 
supports attribute type and object class definitions at this time.

=back 4

=head1 ADDING GRAMMERS

Additional grammers may be used by assigning the BNF (as needed 
for C<Parse::RecDescent>) in the global C<%Config::LDAP::grammers>.

    $Config::LDAP::grammers{$grammer} -> {pre} = sub { ... };
    $Config::LDAP::grammers{$grammer} -> {grammer} = q{ ... };
    $Config::LDAP::grammers{$grammer} -> {post} = sub { ... };

The top rule for the grammer must be C<Schema>.
The C<pre> and C<post> subroutines are only called if they are 
defined.  The C<pre> subroutine is passed a copy of the file and 
should return the processed string.  The C<post> subroutine is 
passed the product of the parse and should return an array 
reference of hashes with the following keys.

It is also recommended that you look at the source for this 
module to see how the included grammers are implemented.

=head2 Attribute Types

Most of the information expected in the hashes is described in RFC 2252.

=over 4

=item _type

This should be set to `attributetype' to indicate that this is 
describing an attribute type.

=item collective

The attribute type is not collective by default.  Set this to 
true to make the attribute type collective.

=item desc

This is a string describing the attribute type.

=item equality

This is the C<oid> or C<name> of the rule governing matching for 
the attribute type.

=item name

This is the name commonly used in lieu of the oid for the attribute type.

=item no-user-modification

The attribute type defaults to user modifiable.  Set this to true 
to disallow user modification.

=item obsolete

Set this to true to mark the attribute type as obsolete.  Does 
not affect functionality but is for informational purposes only.

=item oid

The attribute type identifier.

=item ordering

This is the C<oid> or C<name> of the rule governing ordering for 
the attribute type.

=item short-forms

This is a list of strings that are considered aliases for the C<name>.

=item single-value

The attribute type is multi-valued by default.  Set this to true 
to restrict the attribute type to being single-valued.

=item substr

This is the oid of the rule governing substring matching.

=item sup

This is the C<oid> or C<name> of the parent attribute type from 
which this attribute type is derived.

=item syntax

=item usage

=back 4

=head2 Object Classes

=over 4

=item _type

This should be set to `objectclass' to indicate that this is 
describing an object class.

=item abstract

The object class is C<structural> by default.  Set this to true 
(and C<structural> and C<auxiliary> to false) to make this an 
abstract object class.

=item auxiliary

The object class is C<structural> by default.  Set this to true
(and C<structural> and C<abstract> to false) to make this an
auxiliary object class.

=item desc

=item may

This is a list of attribute types that MAY be in an object of 
this object class.

=item must

This is a list of attribute types that MUST be in an object of 
this object class.

=item name

=item obsolete

=item oid

The object class identifier.

=item sup

This is a list of C<oid>s and/or C<name>s of parent object 
classes from which this object class is derived.

=item structural

The object class is C<structural> by default.  As long as 
C<abstract> and C<auxiliary> are false, the class will remain 
structural.

=back 4

=head1 BUGS

Known to abound, but please let the author know of any really 
nasty ones.  This is an alpha release, which means it works on 
some input but might not on other.  This module is under 
development and the grammers will become more complete over the 
next few versions.

Fortunately, this module does not modify anything in the filesystem.

=head2 RFC2522 Grammer

Terms whose identifier begins with `X-' are not supported.  These 
are for private experimental use anyway.  Support should not be 
expected any time soon for these terms.

=head1 SEE ALSO

L<Parse::RecDescent>,
RFC 2252.

=head1 AUTHOR

James Smith <jgsmith@jamesmith.com>

=head1 COPYRIGHT

Copyright (C) 2001 Texas A&M University.  All Rights Reserved.
 
This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

