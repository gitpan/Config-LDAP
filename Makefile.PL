use ExtUtils::MakeMaker;
# $Id: Makefile.PL,v 1.1 2001/09/24 20:18:44 jgsmith Exp $

WriteMakefile( NAME => 'Config::LDAP',
               VERSION_FROM => 'lib/Config/LDAP.pm',
               PREREQ_PM =>    { Parse::RecDescent => 1.80,
                               },
               dist         => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
             );
