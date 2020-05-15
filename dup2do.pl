#!/usr/local/bin/perl -w
#------------------------------------------------------------------------------
# Licensed Materials - Property of IBM (C) Copyright IBM Corp. 2010, 2010
# All Rights Reserved US Government Users Restricted Rights - Use, duplication
# or disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#------------------------------------------------------------------------------

#  perl dup2do.pl
#
#  Create setagentconnection commands to recify duplicate agents.
#  And redo distribution/MSL for renamed agents
#
#  john alvord, IBM Corporation, 1 May 2020
#  jalvord@us.ibm.com
#
# tested on Windows Strawberry Perl 5.28.1
# Should work on Linux/Unix but not yet tested
#
# $DB::single=2;   # remember debug breakpoint

## todos
##   add support for situation groups

#use warnings::unused; # debug used to check for unused variables
use strict;
use warnings;
use Data::Dumper;               # debug only

my $gVersion = "0.50000";
my $gWin = (-e "C://") ? 1 : 0;    # 1=Windows, 0=Linux/Unix

  # agent suffixes which represent distributed OS Agents
my %agtosx = ( 'NT' => 1,
               'LZ' => 1,
               'KUX' => 1,
             );

my $oneline;

my $opt_dupall;
my $opt_dupsleep;

my %dupallx = ();

while (@ARGV) {
   if ($ARGV[0] eq "-h") {
      &GiveHelp;                        # print help and exit
   }
   if ($ARGV[0] eq "-dupall") {
      $opt_dupall = 1;
      shift(@ARGV);
      if (defined $ARGV[0]) {
         if (substr($ARGV[0],0,1) ne "-") {
            $dupallx{$ARGV[0]} = 1;
            shift(@ARGV);
         }
      }
      shift(@ARGV);
   } elsif ($ARGV[0] eq "-dupsleep") {
      shift(@ARGV);
      if (defined $ARGV[0]) {
         if (substr($ARGV[0],0,1) ne "-") {
            $opt_dupsleep = $ARGV[0];
            shift(@ARGV);
         }
      }
   }
}

$opt_dupall = 0 if !defined $opt_dupall;
$opt_dupsleep = 0 if !defined $opt_dupsleep;




# 1) read in the dedup.csv file so sitinfo.csv can be read selectively
#    The dedup.csv file is created by TEMS Audit when -dup option specified
# Example lines
# aia_au_hostname:NT,ip.spipe:#10.113.88.51,
# aia_au_hostname:NT,ip.spipe:#10.60.41.26,
# aia_au_hostname:NT,ip.spipe:#10.9.121.100,
# aia_au_hostname:NT,ip.spipe:#10.13.192.161,
# MSSQLSERVER:aia_sg_sgdcwpwsql01,ip.spipe:#10.105.171.33,
# MSSQLSERVER:aia_sg_sgdcwpwsql01,ip.spipe:#10.105.171.34,
# aia_id_iddciplpft010:LZ,ip.spipe:#10.132.161.80,
# aia_id_iddciplpft010:LZ,ip.spipe:#10.132.187.105,

my %agentx = ();                     # data referencing potential duplicate agents
my %systemx = ();                    # data about agents and systems

my $dedup_fn = "dedup.csv";
die "no dedup,csv file" if ! -e $dedup_fn;
open(DDUP, "< $dedup_fn") || die("Could not open dedup report  $dedup_fn\n");
# Primary:GDCUWVC0366:NT,GDCUWVC0366-DUP1,,
while ($oneline = <DDUP>){
   last if !defined $oneline;
   $oneline =~ /([^,]*),([^,]*),/;
   my $inode = $1;
   my $ihostaddr = $2;
   my $iip = 0;

   # calculate the ip address of the duplicate agent. Some hostaddrs have port numbers and some not.
   if (index($ihostaddr,"[") != -1) {
      $ihostaddr =~ /:#(\S+)\[(\S*)\]/;
      $iip = $1 if defined $1;                # a $1 does not survive and if or else clause
   } else {
      $ihostaddr =~ /#(\S*)/;
      $iip = $1 if defined $1;
   }

   my $ihostname = "";                       # the calculated hostname based on agent name.
   my $ipc = "";
   my $tnode = $inode;
   $tnode =~ s/[^:]//g;
   my $ncolons = length($tnode);
   my @wnodes = split(":",$inode);
   if ($ncolons == 0) {
      $ihostname = $inode;
   } elsif ($ncolons == 1) {
      $ihostname = $wnodes[0];
      $ipc       = $wnodes[1];
      $ipc = "" if !defined $wnodes[1];
   } elsif ($ncolons == 2) {
      $ihostname = $wnodes[1];
      $ipc       = $wnodes[2];
      $ipc = "" if !defined $wnodes[2];
   } elsif ($ncolons >= 3) {
      $ihostname = $wnodes[2];
      $ipc       = $wnodes[3];
      $ipc = "" if !defined $wnodes[3];
   }
   my $agent_ref = $agentx{$inode};                  # is this a new agent name
   if (!defined $agent_ref) {
      my %agentref = (
                        count => 0,                  # count how many
                        ipx => {},                   # track all the ip addresses [systems]
                        sitx => {},                  # trace situations distributed to this system
                        hostname => $ihostname,      # calculated hostname
                        pc => $ipc,                  # Agent suffix
                        newagents => [],             # all new agent names, ones with -DUPn appended
                     );
      $agent_ref = \%agentref;
      $agentx{$inode} = \%agentref;
   }
   $agent_ref->{count} += 1;                         # count, if only one in the end we can ignore
   $agent_ref->{ipx}{$iip} = 1;                      # track ip addresses [systems]

   my $system_ref = $systemx{$iip};                  # Separately track what is happening per system
   if (!defined $system_ref) {
      my %systemref = (
                         count => 0,                 # count of ITM agents running on the system
                         agents => [],               # array of agent running
                         osagent => "",              # if there is a OS Agent, record its name here
                      );
      $system_ref = \%systemref;
      $systemx{$iip} = \%systemref;
   }
   $system_ref->{count} += 1;                        # count of agents on system
   push @{$system_ref->{agents}},$inode;             # add one more to the lists
   $system_ref->{osagent} = $inode if defined $agtosx{$agent_ref->{pc}}; # set os agent name if suffix is correct
}
close(DDUP);


# 2) create setagent connection command files to change the apparent hostname on all but first example

my $opt_dedup_sh;                               # names of output files, unix-style sh and Windows syle cmd
my $opt_dedup_cmd;
$opt_dedup_cmd = "dedup.cmd";
$opt_dedup_sh  = "dedup.sh";
open DEPSH, ">$opt_dedup_sh" or die "can't open $opt_dedup_sh: $!";
binmode(DEPSH);
open DEPCMD, ">$opt_dedup_cmd" or die "can't open $opt_dedup_cmd: $!";

my $dup_ct;
foreach my $f (keys %agentx) {                                                     # look at each agent
   my $agent_ref=$agentx{$f};
   next if $agent_ref->{count} < 2;                                                # ignore if less than two examples
   $dup_ct = 0;                                                                    # set counter - control working on second and later agents
   foreach my $g (keys %{$agent_ref->{ipx}}) {
      my $system_ref = $systemx{$g};
      $dup_ct += 1;                                                                # Add one to counter
      next if $dup_ct < 2;
      next if $f ne $system_ref->{osagent};                                        # skip processing on the first one
      my $iscope = "-t " . $agent_ref->{pc};                                       # working on just OS Agent
      $iscope = "-a" if defined $dupallx{$agent_ref->{hostname}};                  # working on all agents where OS Agent is running
      my $name_ct = $dup_ct - 1;                                                   # calculate the duplicate hostname
      my $duphostname = $agent_ref->{hostname} . "-DUP" . $name_ct;                # appending -DUPn to previous hostname
      my $outsh  = "./tacmd setagentconnection -n $f $iscope ";                    # tacmd setagentconnection for Linux/Unix
      $outsh .= "-e CTIRA_HOSTNAME=" . $duphostname . " ";
      $outsh .= "CTIRA_SYSTEM_NAME=" . $duphostname . " ";
      my $outcmd = "tacmd setagentconnection -n $f $iscope ";                      # tacmd setagentconnection for Windows
      $outcmd .= "-e CTIRA_HOSTNAME=" . $duphostname . " ";
      $outcmd .= "CTIRA_SYSTEM_NAME=" . $duphostname . " ";
      print DEPSH  "$outsh\n";
      print DEPCMD "$outcmd\n";
      print DEPSH "sleep $opt_dupsleep\n" if $opt_dupsleep != 0;                               # sleep in Linux/Unix
      print DEPCMD "choice /C YNC /D Y /N /T $opt_dupsleep >NUL 2>&1\n" if $opt_dupsleep != 0; # sleep in Windows
      my $newagent = $f;
      $newagent =~ s/$agent_ref->{hostname}/$duphostname/;                         # remember the new agent name
      push @{$agent_ref->{newagents}},$newagent;
   }
}
close(DEPSH);
close(DEPCMD);


# 3) extract relevant data from sitinfo.csv
#    stage I - situations involved with duplicated agents
#    stage II - distributions involved with duplicated agents

my %mslx;                                                        # track MSL distribution usage
my %sitdx;                                                       # track Situation distribution usage
my $sitinfo_fn = "sitinfo.csv";

die "no sitinfo.csv report file" if ! -e $sitinfo_fn;
open(INFO, "< $sitinfo_fn") || die("Could not open sitinfo report  $sitinfo_fn\n");

my $l = 0;
while ($oneline = <INFO>){
   last if !defined $oneline;
   $l += 1;
   next if $l < 6;
   last if $oneline eq "";
   $oneline =~ /([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),(.*)/;
   my $isit = $1;
   my $isev = $2;
   my $iip = $3;
   my $inode = $4;
   my $idist = $5;
   my $ipdt = $6;
   last if !defined $inode;
   next if substr($idist,0,3) eq "M|*";                          # for the moment ignore Sitgroup entries
   next if substr($idist,0,4) eq "GM|*";
   my $agent_ref =  $agentx{$inode};                             # skip if the agent involved unknown in the duplicated set
   next if !defined $agent_ref;
   my $sit_ref = $agent_ref->{sitx}{$isit};                      # create a situation record in the $agent_ref hash
   if (!defined $sit_ref) {
      my %sitref = (
                      sev => $isev,
                      ip => $iip,
                      dist => $idist,
                      pdt => $ipdt,
                      l => $l,
                   );
      $sit_ref = \%sitref;
      $agent_ref->{sitx}{$isit} = \%sitref;
   }
   if (substr($idist,0,2) eq "M|") {                             # is this a MSL type distribution?
      $idist =~ /M\|(\S+)\;/;                                    # if so create a $msl_ref which will eventually
      my $imsl = $1;                                             # hold all the related agents
      my $msl_ref = $mslx{$imsl};
      if (!defined $msl_ref) {
         my %mslref = (
                         nodes => {},
                      );
         $msl_ref = \%mslref;
         $mslx{$imsl} = \%mslref;
      }
      $msl_ref->{nodes}{$inode} = 1;                             # the 1 value means it is here because of a duplicated agent

   } elsif (substr($idist,0,2) eq "A|") {                        # is this a Agent style distribution?
      my $sitd_ref = $sitdx{$isit};                              # if so add it to the $sitd_ref distributions
      if (!defined $sitd_ref) {
         my %sitdref = (
                          dists => {},
                       );
         $sitd_ref = \%sitdref;
         $sitdx{$isit} = \%sitdref;
      }
      $sitd_ref->{dists}{$idist} = 1;
   } elsif (substr($idist,0,3) eq "GA|") {                                           # warn about missing sitgroup entries
      warn "situation groups not supported - direct agent assignment for $isit \n"
   } elsif (substr($idist,0,3) eq "GM|") {
      warn "situation groups not supported - MSL assignment for $isit \n"
   }
}

# Second pass to add in sitinfo distribution tags

seek INFO,0, 0;
$l = 0;
while ($oneline = <INFO>){
   last if !defined $oneline;
   $l += 1;
   next if $l < 6;
   last if length($oneline) < 2;
   $oneline =~ /([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),(.*)/;
   my $isit = $1;
   my $isev = $2;
   my $iip = $3;
   my $inode = $4;
   my $idist = $5;
   my $ipdt = $6;
   next if !defined $isit;
   next if !defined $sitdx{$isit};
   my $sitd_ref = $sitdx{$isit};
   next if !defined $sitd_ref;
   $sitd_ref->{dists}{$idist} = 2 if ! defined $sitd_ref->{dists}{$idist};
}
close(INFO);




# 4) Generate tacmd editsit and tacmd editsystemlist commands to add the new names

# first editsystemlists these will be adds

# tacmd editsystemlist {-e|--edit} FILENAME
# {[{-a|--add} SYSTEM ...] [{-d|--delete} SYSTEM ...]}

my $opt_dup2do = "dup2doc.cmd";
my $opt_dup2do_sh  = "dup2doc.sh";
open DP2SH, ">$opt_dup2do_sh" or die "can't open $opt_dup2do_sh: $!";
binmode(DP2SH);
open DP2CMD, ">$opt_dup2do" or die "can't open $opt_dup2do: $!";
print DP2SH  "# Start of Managed System List Cleanup\n";
print DP2CMD "REM Start of Managed System List Cleanup\n";
foreach my $m (keys %mslx) {                                             # for each MSL incolved, collect all the newagent values
   my $msl_ref = $mslx{$m};
   my $systems = "";
   foreach $a (keys %{$msl_ref->{nodes}}) {
      my $agent_ref = $agentx{$a};
      next if !defined $agent_ref;
      next if $#{$agent_ref->{newagents}} == -1;
      my $addnodes = join " ",@{$agent_ref->{newagents}};
      $systems .= $addnodes . " ";
   }
   my $outsh  = "./tacmd editsystemlist -e " . $m . " -a " . $systems;
   my $outcmd = "tacmd editsystemlist -e " . $m . " -a " . $systems;
   print DP2SH  "$outsh\n";
   print DP2CMD "$outcmd\n";
}
print DP2SH  "#\n";
print DP2CMD "REM\n";


# second work on the tacmd editsit.
# this also has to include existing distributons by agent on MSLs

# tacmd editsit
# {-s|--situation} SITNAME
# {-p|--property|--properties} NAME=VALUE
# [-f|--force]

print DP2SH  "# Start of Situation Distribution Cleanup\n";
print DP2CMD "REM Start of Situation Distribution Cleanup\n";
foreach my $s (keys %sitdx) {
   my $sitd_ref = $sitdx{$s};
   my $dists = "";
   foreach my $d (keys %{$sitd_ref->{dists}}) {
      my $sitd_ref = $sitd_ref->{dists}{$d};
      $d =~ /\|(\S+)\;/;
      my $itarget = $1;
      $dists .= " " . $itarget;
      my $agent_ref = $agentx{$itarget};
      next if !defined $agent_ref;
      next if $#{$agent_ref->{newagents}} == -1;
      my $newtargets = join " ",@{$agent_ref->{newagents}};
      $dists .= $itarget . " " .$newtargets;
   }
   my $outsh  = "./tacmd editsit -s $s -p Distribution $dists";
   my $outcmd = "tacmd editsit -s $s -p Distribution $dists";
   print DP2SH  "$outsh\n";
   print DP2CMD "$outcmd\n";
}
close(DP2SH);
close(DP2CMD);

# 5) compose a report for manual corrections
#      first the MSL additions

my $opt_dup2do_csv = "dup2doc.csv";
open DP2CSV, ">$opt_dup2do_csv" or die "can't open $opt_dup2do_csv: $!";
print DP2CSV "* Manual Checklist for ITM repair after duplicate agent recovery dup2do.sh or dup2do.cmd\n";
print DP2CSV "* First stage is repairing the Managed System Lists\n";
foreach my $m (keys %mslx) {
   my $msl_ref = $mslx{$m};
   print DP2CSV "MSL,$m,,\n";
   foreach $a (keys %{$msl_ref->{nodes}}) {
      my $agent_ref = $agentx{$a};
      next if !defined $agent_ref;
      foreach my $n (@{$agent_ref->{newagents}}) {
         print DP2CSV "add,$n,\n";
      }
   }
}

#      second the Agent distributions
print DP2CSV "*\n";
print DP2CSV "* Second stage is repairing the Situation Distributions\n";
foreach my $s (keys %sitdx) {
   my $sitd_ref = $sitdx{$s};
   print DP2CSV "SIT,$s,,\n";
   my $dists = "";
   foreach my $d (keys %{$sitd_ref->{dists}}) {
      next if $sitd_ref->{dists}{$d} != 1;
      my $sitd_ref = $sitd_ref->{dists}{$d};
      $d =~ /\|(\S+)\;/;
      my $itarget = $1;
      my $agent_ref = $agentx{$itarget};
      next if !defined $agent_ref;
      foreach my $n (@{$agent_ref->{newagents}}) {
         print DP2CSV "add,$n,\n";
      }
   }
}
close(DP2CSV);

exit 0;
