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
#  Create several reports to guide the recovery.
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

my $gVersion = "0.54000";
my $gWin = (-e "C://") ? 1 : 0;    # 1=Windows, 0=Linux/Unix

sub init_txt;
sub init_lst;
my $ll;

  # agent suffixes which represent distributed OS Agents
my %agtosx = ( 'NT' => 1,
               'LZ' => 1,
               'KUX' => 1,     # from agent name
               'UX' => 1,      # from TNODESAV PRODUCT column
             );

my $oneline;
my $sx;
my $i;

my $tx;                                  # TEMS information
my $temsi = -1;                          # count of TEMS
my @tems = ();                           # Array of TEMS names
my %temsx = ();                          # Hash to TEMS index
my @tems_version = ();                   # TEMS version number

my $mx;                                  # index
my $magenti = -1;                        # count of managing agents
my @magent = ();                         # name of managing agent
my %magentx = ();                        # hash from managing agent name to index
my @magent_subct = ();                   # count of subnode agents
my @magent_sublen = ();                  # length of subnode agent list
my @magent_tems_version = ();            # version of managing agent TEMS
my @magent_tems = ();                    # TEMS name where managing agent reports



# TNODELST type V record data           Alive records - list thrunode most importantly
my $vlx;                                # Access index
my $nlistvi = -1;                       # count of type V records
my @nlistv = ();                        # node name
my %nlistvx = ();                       # hash from name to index
my @nlistv_thrunode = ();               # agent thrunode
my @nlistv_tems = ();                   # TEMS if thrunode is agent
my @nlistv_ct = ();                     # count of agents
my @nlistv_lstdate = ();                # last update date

my %agentx = ();                     # Data referencing potential duplicate agents
my %systemx = ();                    # Data about agents and systems
my %managex = ();                    # Data about managing agents
my %subnodex = ();                   # Data from subnode agent view
my %nodex = ();                      # Data from nodes from TNODESAV
my %dupnodex = ();                   # Systems which showed duplicate evidence
my %zosagtx = ();                    # Track and ignore z/OS agents
my %osystemx = ();                   # ip address => OS Agent lookup

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
$opt_dupsleep = 600 if !defined $opt_dupsleep;

# 1) if QA1DNSAV.DB.TXT or QA1DNSAV.DB.LST is present read in that data and create nodex and systemx reference hashes
my $opt_txt_tnodesav = "QA1DNSAV.DB.TXT";
my $opt_lst_tnodesav = "QA1DNSAV.DB.LST";
my $opt_txt_tnodelst = "QA1DNSAV.DB.TXT";
my $opt_lst_tnodelst = "QA1DNSAV.DB.LST";
my $tnodesav_ct = 0;
sub init_txt;
sub init_lst;
if (-e $opt_txt_tnodesav) {
   init_txt();
} elsif (-e $opt_lst_tnodesav) {
   init_lst();
}


# 2) read in the dedup.csv file so sitinfo.csv can be read selectively
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
#
# Following is a case where a Tivoli Log Agent is a subnode to a managing agent
# first entry is the subnode agent and second is the managing agent.
# this is where duplicate subnode agents may be observed.
#LO:szabwa4_ePIMS_CPM_QA_bwa4,ePIMS_QA_ecims_bwa4:szabwa4:szab,
#
# Following is a z/OS sna case which is ignored at present
#XEDB2:P20E,sna:#SCKAISER.K0ED5NC.CANCTDCS.SNASOCKETS,

my $dedup_fn = "dedup.csv";
die "no dedup,csv file" if ! -e $dedup_fn;
my $dedup_fh;
open $dedup_fh, "<", $dedup_fn || die("Could not open dedup report  $dedup_fn\n");
my @ddup = <$dedup_fh>;                   # Data read once and processed twice
close $dedup_fh;

# Pass one to collect managing node and subnode information
$ll = 0;
foreach $oneline (@ddup) {
   last if !defined $oneline;
   $ll += 1;
   $oneline =~ /([^,]*),([^,]*),/;
   my $inode = $1;
   my $ihostaddr = $2;
   next if $ihostaddr eq "";                    # ignore blanks
   next if substr($ihostaddr,0,4) eq "sna:";    # ignore sna: for now
   next if index($ihostaddr,"#") != -1;         # first pass ignore lines without hostaddr
   next if defined $zosagtx{$inode};            # ignore z/os agents
   my $manage_ref = $managex{$ihostaddr};
   if (!defined $manage_ref) {
      my %manageref = (
                         hostaddr => "",
                         product => "",
                         version => "",
                         subnodes => {},
                         ll => $ll,
                      );
      $manage_ref = \%manageref;
      $managex{$ihostaddr} = \%manageref;
      my $node_ref = $nodex{$inode};
      if (defined $node_ref) {
         $manage_ref->{hostaddr} = $node_ref->{hostaddr};
         $manage_ref->{product} = $node_ref->{product};
         $manage_ref->{version} = $node_ref->{version};
      }
   }
   $manage_ref->{subnodes}{$inode} = 1;
   my $subnode_ref = $subnodex{$inode};
   if (!defined $subnode_ref) {
      my %subnoderef = (
                          manageds => {},
                       );
      $subnode_ref = \%subnoderef;
      $subnodex{$inode} = \%subnoderef;
   }
   $subnode_ref->{manageds}{$ihostaddr} = 1;
}


# Pass two to calculate hostname from the Agent name
$ll = 0;
foreach $oneline (@ddup) {
   last if !defined $oneline;
   $ll += 1;
   $oneline =~ /([^,]*),([^,]*),/;
   my $inode = $1;
   my $ihostaddr = $2;
   my $iip = 0;
   next if substr($ihostaddr,0,4) eq "sna:";
   next if index($ihostaddr,"#") == -1;
   next if defined $subnodex{$inode};
   next if defined $zosagtx{$inode};            # ignore z/os agents

   # calculate the ip address of the duplicate agent. Some hostaddrs have port numbers and some not.
   if (index($ihostaddr,"[") != -1) {
      $ihostaddr =~ /:#(\S+)\[(\S*)\]/;
      $iip = $1 if defined $1;                # a $1 does not survive and if or else clause
   } else {
      $ihostaddr =~ /#(\S*)/;
      $iip = $1 if defined $1;
   }
   $dupnodex{$inode} = 1;

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
                                                     # Could be calculated in new_tnodesav
   if (!defined $system_ref) {
      my %systemref = (
                         count => 0,                 # count of ITM agents running on the system
                         agents => [],               # array of agent running
                         osagent => "",              # if there is a OS Agent, record its name here
                         tnodesav_lines => [],       # lines from TNODESAV if present
                         dedup_lines => [],          # lines from DEDUP.CSV
                      );
      $system_ref = \%systemref;
      $systemx{$iip} = \%systemref;
   }
   $system_ref->{count} += 1;                        # count of agents on system
   $system_ref->{osagent} = $inode if defined $agtosx{$ipc}; # record osagent if present
   push @{$system_ref->{agents}},$inode;             # add one more to the lists
   push @{$system_ref->{dedup_lines}},$oneline;      # add one more to the lists
}


# 3) create the subnode duplication report

my $opt_dup2do_sub_csv = "dup2do_subnode.csv";
my $dup2do_sub_fh;
open $dup2do_sub_fh, ">", $opt_dup2do_sub_csv or die "can't open $opt_dup2do_sub_csv: $!";
print $dup2do_sub_fh "* Subnode duplication report\n";
print $dup2do_sub_fh "Subnode, Manage_node, Product, Version, Hostaddr\n";
foreach my $s (keys %subnodex) {
   my $subnode_ref = $subnodex{$s};
   my $manage_ct = scalar keys %{$subnode_ref->{manageds}};
   next if $manage_ct < 2;
   foreach my $m (keys %{$subnode_ref->{manageds}}) {
      my $manage_ref = $managex{$m};
      my $node_ref = $nodex{$m};
      next if substr($manage_ref->{hostaddr},0,4) eq "sna:";
      my $oline = $s . ",";
      $oline .= $m . ",";
      $oline .= $node_ref->{product} . ",";
      $oline .= $node_ref->{version} . ",";
      $oline .= $node_ref->{hostaddr} . ",";
      print$dup2do_sub_fh "$oline\n";
   }
   print $dup2do_sub_fh "count=$manage_ct,\n";
   print $dup2do_sub_fh "\n";
}
close $dup2do_sub_fh;

# 4) compose a dedup_plus.csv with tnodesav data report
#    That can help figure out some complex cases

if ($tnodesav_ct > 0) {
   my $opt_dup2do_plus_csv = "dup2do_plus.csv";
   my $dup2do_plus_fh;
   open $dup2do_plus_fh, ">", $opt_dup2do_plus_csv or die "can't open $opt_dup2do_plus_csv: $!";
   print $dup2do_plus_fh "* DEDUP.CSV with embedded TNODESAV data\n";
   print $dup2do_plus_fh "IP,Source,dup=DEDUP.CSV msn=TNODESAV data\n";
   foreach my $s (sort { $a cmp $b } keys %systemx) {
      my $system_ref = $systemx{$s};
      my $isdup = 0;
      foreach my $a (@{$system_ref->{agents}}) {
         next if !defined $dupnodex{$a};
         $isdup = 1;
         last;
      }
      next if $isdup == 0;
      foreach my $line (@{$system_ref->{dedup_lines}}){
         print $dup2do_plus_fh "$s,dup,$line";
      }
      foreach my $line (@{$system_ref->{tnodesav_lines}}){
         print $dup2do_plus_fh "$s,$line\n";
      }
      print $dup2do_plus_fh "\n";
   }
   close $dup2do_plus_fh;
}


# 5) create setagent connection command files to change the apparent hostname on all but first example

my $opt_dedup_sh;                               # names of output files, unix-style sh and Windows syle cmd
my $dedup_sh_fh;
my $opt_dedup_cmd;
my $dedup_cmd_fh;
$opt_dedup_cmd = "dedup.cmd";
$opt_dedup_sh  = "dedup.sh";
open $dedup_sh_fh, ">", $opt_dedup_sh or die "can't open $opt_dedup_sh: $!";
binmode $dedup_sh_fh ;
open $dedup_cmd_fh, ">", $opt_dedup_cmd or die "can't open $opt_dedup_cmd: $!";

my $dup_ct;
foreach my $f (keys %agentx) {                                                     # look at each agent
   my $agent_ref=$agentx{$f};
   next if $agent_ref->{count} < 2;                                                # ignore if less than two examples
   my $tot_ct = 0;
   my $sys = "";
   foreach my $g (keys %{$agent_ref->{ipx}}) {                                     # calculate number of OS Agents
      my $system_ref = $systemx{$g};
      $sys .= $g . " ";
      $tot_ct += 1 if $system_ref->{osagent} ne "";
   }
   if ($tot_ct == 0) {   # duplicate agent without OS Agent
      chop $sys if $sys ne "";
      my $outsh  = "# Agent $f on systems[$sys] has no identified OS Agents";        # tacmd setagentconnection for Linux/Unix
      my $outcmd  = "REM Agent $f on systems[$sys] has no identified OS Agents";        # tacmd setagentconnection for Linux/Unix
      print $dedup_sh_fh "$outsh\n";
      print $dedup_cmd_fh "$outcmd\n";
      next;
   }
   # first stage, handle duplicate os agents
   $dup_ct = 0;                                                                    # set counter - control working on second and later agents
   foreach my $g (keys %{$agent_ref->{ipx}}) {
      my $system_ref = $systemx{$g};
      next if $f ne $system_ref->{osagent};                                        # skip processing on the first one
      $dup_ct += 1;                                                                # Add one to counter
      next if $dup_ct < 2;
      my $iscope = "-t " . $agent_ref->{pc};                                       # working on just OS Agent
      $iscope = "-a" if defined $dupallx{$agent_ref->{hostname}};                  # working on all agents where OS Agent is running
      my $name_ct = $dup_ct - 1;                                                   # calculate the duplicate hostname
      my $iname =  $agent_ref->{hostname};
      my $headway = 32 - length($iname);
      my $pname =  "-DUP" . $name_ct;
      my $plen = length($pname);
      my $duphostname;
      if ($plen <= $headway) {
         $duphostname = $iname . $pname;
      } else {
         my $dpos = length($iname) - length($pname);
         $duphostname = substr($iname,0,$dpos) . $pname;
      }
      my $outsh  = "./tacmd setagentconnection -n $f $iscope ";                    # tacmd setagentconnection for Linux/Unix
      $outsh .= "-e CTIRA_HOSTNAME=" . $duphostname . " ";
      $outsh .= "CTIRA_SYSTEM_NAME=" . $duphostname . " ";
      my $outcmd = "tacmd setagentconnection -n $f $iscope ";                      # tacmd setagentconnection for Windows
      $outcmd .= "-e CTIRA_HOSTNAME=" . $duphostname . " ";
      $outcmd .= "CTIRA_SYSTEM_NAME=" . $duphostname . " ";
      print $dedup_sh_fh "$outsh\n";
      print $dedup_cmd_fh "$outcmd\n";
      if ($dup_ct < $tot_ct) {
         print $dedup_sh_fh "sleep $opt_dupsleep\n" if $opt_dupsleep != 0;                               # sleep in Linux/Unix
         print $dedup_cmd_fh "choice /C YNC /D Y /N /T $opt_dupsleep >NUL 2>&1\n" if $opt_dupsleep != 0; # sleep in Windows
      }
      my $newagent = $f;
      $newagent =~ s/$agent_ref->{hostname}/$duphostname/;                         # remember the new agent name
      push @{$agent_ref->{newagents}},$newagent;
   }

   # second stage, handle duplicate non-os agents where an os agent exists on that same system
   # The change hostname can happen if an OS Agent is present on the system
   $dup_ct = 0;                                                                    # set counter - control working on second and later agents
   foreach my $g (keys %{$agent_ref->{ipx}}) {
      my $system_ref = $systemx{$g};
      next if $f eq $system_ref->{osagent};                                        # Ignore OS Agents
      $dup_ct += 1;                                                                # Add one to counter and skip first
      my $iosagent = $osystemx{$g};
      if (!defined $iosagent) {
         if ($dup_ct >= 2) {                                                         # Maybe the next one has an OS Agent
            my $outsh  = "# Agent $f on systems[$g] has no identified OS Agents - reconfigure manually";        # tacmd setagentconnection for Linux/Unix
            my $outcmd  = "REM Agent $f on systems[$g] has no identified OS Agents - reconfigure manually";     # tacmd setagentconnection for Linux/Unix
            print $dedup_sh_fh "$outsh\n";
            print $dedup_cmd_fh "$outcmd\n";
         }
         next;
      }
      next if $dup_ct < 2;                                                         # Skiping the first
      my $iscope = "-t " . $agent_ref->{pc};                                       # working on just OS Agent
      $iscope = "-a" if defined $dupallx{$agent_ref->{hostname}};                  # working on all agents where OS Agent is running
      my $name_ct = $dup_ct - 1;                                                   # calculate the duplicate hostname
      my $iname =  $agent_ref->{hostname};
      my $headway = 32 - length($iname);
      my $pname =  "-DUP" . $name_ct;
      my $plen = length($pname);
      my $duphostname;
      if ($plen <= $headway) {
         $duphostname = $iname . $pname;
      } else {
         my $dpos = length($iname) - length($pname);
         $duphostname = substr($iname,0,$dpos) . $pname;
      }
      my $outsh  = "./tacmd setagentconnection -n $iosagent $iscope ";                    # tacmd setagentconnection for Linux/Unix
      $outsh .= "-e CTIRA_HOSTNAME=" . $duphostname . " ";
      $outsh .= "CTIRA_SYSTEM_NAME=" . $duphostname . " ";
      my $outcmd = "tacmd setagentconnection -n $iosagent $iscope ";                      # tacmd setagentconnection for Windows
      $outcmd .= "-e CTIRA_HOSTNAME=" . $duphostname . " ";
      $outcmd .= "CTIRA_SYSTEM_NAME=" . $duphostname . " ";
      print $dedup_sh_fh "$outsh\n";
      print $dedup_cmd_fh "$outcmd\n";

      # no need to wait after OS Agent changes name of non-os agent
      my $newagent = $f;
      $newagent =~ s/$agent_ref->{hostname}/$duphostname/;                         # remember the new agent name
      push @{$agent_ref->{newagents}},$newagent;
   }
}
close $dedup_sh_fh;
close $dedup_cmd_fh;


# 6) extract relevant data from sitinfo.csv
#    stage I - situations involved with duplicated agents
#    stage II - distributions involved with duplicated agents

my %mslx;                                                        # track MSL distribution usage
my %sitdx;                                                       # track Situation distribution usage
my $sitinfo_fn = "sitinfo.csv";
my $sitinfo_fh;

die "no sitinfo.csv report file" if ! -e $sitinfo_fn;
open $sitinfo_fh, "<", $sitinfo_fn || die("Could not open sitinfo report  $sitinfo_fn\n");

my $l = 0;
while ($oneline = <$sitinfo_fh>){
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
                         srcs => {},
                      );
         $msl_ref = \%mslref;
         $mslx{$imsl} = \%mslref;
      }
      $msl_ref->{nodes}{$inode} = 1;                             # the 1 value means it is here because of a duplicated agent
      my $isrc = "M";
      $msl_ref->{srcs}{$isrc} = 1;                             # the 1 value means it is here because of a duplicated agent

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
      my $isrc = "A";
      $sitd_ref->{srcs}{$isrc} = 1;                             # the 1 value means it is here because of a duplicated agent
   } elsif (substr($idist,0,3) eq "GA|") {                                           # warn about missing sitgroup entries
      $idist =~ /GA\|(\S+)\|(\S+)\;/;                                    # if so create a $msl_ref which will eventually
      my $imsl = $1;                                             # hold all the related agents
      my $igrp = $2;
      my $sitd_ref = $sitdx{$isit};                              # if so add it to the $sitd_ref distributions
      if (!defined $sitd_ref) {
         my %sitdref = (
                          dists => {},
                       );
         $sitd_ref = \%sitdref;
         $sitdx{$isit} = \%sitdref;
      }
      $sitd_ref->{dists}{$idist} = 1;
   } elsif (substr($idist,0,3) eq "GM|") {                        # is this a MSL from Sitgroup type distribution?
      $idist =~ /GM\|(\S+)\|(\S+)\;/;                                    # if so create a $msl_ref which will eventually
      my $imsl = $1;                                             # hold all the related agents
      my $igrp = $2;
      my $msl_ref = $mslx{$imsl};
      if (!defined $msl_ref) {
         my %mslref = (
                         nodes => {},
                         srcs => {},
                      );
         $msl_ref = \%mslref;
         $mslx{$imsl} = \%mslref;
      }
      $msl_ref->{nodes}{$inode} = 1;                             # the 1 value means it is here because of a duplicated agent
      my $isrc = "GM" . "|" . $igrp;                             # source is a Sitgroup using MSL
      $msl_ref->{srcs}{$isrc} = 1;                               # the 1 value means it is here because of a duplicated agent
   }
}

# Second pass to add in sitinfo distribution tags
# that is needed for the tacmd editSit where the whole Agent distribution is needed

seek $sitinfo_fh,0, 0;
$l = 0;
while ($oneline = <$sitinfo_fh>){
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
close $sitinfo_fh;




# 7) Generate tacmd editsit and tacmd editsystemlist commands to add the new names

# first editsystemlists these will be adds

# tacmd editsystemlist {-e|--edit} FILENAME
# {[{-a|--add} SYSTEM ...] [{-d|--delete} SYSTEM ...]}

my $opt_dup2do_edit_cmd = "dup2do_edit.cmd";
my $dup2do_edit_cmd_fh;
my $opt_dup2do_edit_sh  = "dup2do_edit.sh";
my $dup2do_edit_sh_fh;
open $dup2do_edit_sh_fh, ">", $opt_dup2do_edit_sh or die "can't open $opt_dup2do_edit_sh: $!";
binmode $dup2do_edit_sh_fh;
open $dup2do_edit_cmd_fh, ">$opt_dup2do_edit_cmd" or die "can't open $opt_dup2do_edit_cmd: $!";
print $dup2do_edit_sh_fh "# Start of Managed System List Cleanup\n";
print $dup2do_edit_cmd_fh "REM Start of Managed System List Cleanup\n";
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
   print $dup2do_edit_sh_fh "$outsh\n";
   print $dup2do_edit_cmd_fh "$outcmd\n";
}
print $dup2do_edit_sh_fh "#\n";
print $dup2do_edit_cmd_fh "REM\n";


# second work on the tacmd editsit section.
# this also has to include existing distributons by agent on MSLs

# tacmd editsit
# {-s|--situation} SITNAME
# {-p|--property|--properties} NAME=VALUE
# [-f|--force]

print $dup2do_edit_sh_fh "# Start of Situation Distribution Cleanup\n";
print $dup2do_edit_cmd_fh "REM Start of Situation Distribution Cleanup\n";
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
   print $dup2do_edit_sh_fh "$outsh\n";
   print $dup2do_edit_cmd_fh "$outcmd\n";
}
close $dup2do_edit_sh_fh;
close $dup2do_edit_cmd_fh;

# 8) compose a report to show manual corrections
#      first the MSL additions

my $opt_dup2do_csv = "dup2do_correct.csv";
my $dup2do_csv_fh;
open $dup2do_csv_fh, ">", $opt_dup2do_csv or die "can't open $opt_dup2do_csv: $!";
print $dup2do_csv_fh "* Manual Checklist for ITM repair after duplicate agent recovery dup2do.sh or dup2do.cmd\n";
print $dup2do_csv_fh "* First stage is repairing the Managed System Lists\n";
print $dup2do_csv_fh "Type,MSL,Dist,\n";
print $dup2do_csv_fh "Action,Node,\n";
foreach my $m (keys %mslx) {
   my $msl_ref = $mslx{$m};
   my $pdist = "";
   foreach my $d (keys %{$msl_ref->{srcs}}) {
      $pdist .= $d . " ";
   }
   chop $pdist if $pdist ne "";
   print $dup2do_csv_fh "MSL,$m,$pdist,\n";
   foreach $a (keys %{$msl_ref->{nodes}}) {
      my $agent_ref = $agentx{$a};
      next if !defined $agent_ref;
      foreach my $n (@{$agent_ref->{newagents}}) {
         print $dup2do_csv_fh "add,$n,\n";
      }
   }
}

#      second the Agent distributions
print $dup2do_csv_fh "*\n";
print $dup2do_csv_fh "* Second stage is repairing the Situation Distributions\n";
print $dup2do_csv_fh "Type,SIT,Dist,\n";
print $dup2do_csv_fh "Action,Node,\n";
foreach my $s (keys %sitdx) {
   my $sitd_ref = $sitdx{$s};
   my $pdist = "";
   foreach my $d (keys %{$sitd_ref->{dists}}) {
      $pdist .= $d . " ";
   }
   chop $pdist if $pdist ne "";
   print $dup2do_csv_fh "SIT,$s,$pdist,\n";
   my $dists = "";
   foreach my $d (keys %{$sitd_ref->{dists}}) {
      next if $sitd_ref->{dists}{$d} != 1;
      my $sitd_ref = $sitd_ref->{dists}{$d};
      $d =~ /\|(\S+)\;/;
      my $itarget = $1;
      my $agent_ref = $agentx{$itarget};
      next if !defined $agent_ref;
      foreach my $n (@{$agent_ref->{newagents}}) {
         print $dup2do_csv_fh "add,$n,\n";
      }
   }
}
close $dup2do_csv_fh;

exit 0;

sub new_tnodelstv {
   my ($inodetype,$inodelist,$inode,$ilstdate) = @_;
   # The $inodelist is the managed system name. Record that data
   $vlx = $nlistvx{$inodelist};
   if (!defined $vlx) {
      $nlistvi++;
      $vlx = $nlistvi;
      $nlistv[$vlx] = $inodelist;
      $nlistvx{$inodelist} = $vlx;
      $nlistv_thrunode[$vlx] = $inode;
      $nlistv_tems[$vlx] = "";
      $nlistv_ct[$vlx] = 0;
      $nlistv_lstdate[$vlx] = $ilstdate;
   }

   # The $inode is the thrunode, capture that data.
   $nlistv_ct[$vlx] += 1;
   $tx = $temsx{$inode};      # is thrunode a TEMS?
   # keep track of managing agent - which have subnodes
   # before ITM 623 FP2 this was limited in size and needs an advisory
   if (!defined $tx) {        # if not it is a managing agent
      $mx = $magentx{$inode};
      if (!defined $mx) {
         $magenti += 1;
         $mx = $magenti;
         $magent[$mx] = $inode;
         $magentx{$inode} = $mx;
         $magent_subct[$mx] = 0;
         $magent_sublen[$mx] = 0;
         $magent_tems_version[$mx] = "";
         $magent_tems[$mx] = "";
      }
      $magent_subct[$mx] += 1;
      # the actual limit is the names in a list with single blank delimiter
      # If the exceeds 32767 bytes, a TEMS crash or other malfunction can happen.
      $magent_sublen[$mx] += length($inodelist) + 1;
   } else {
     # if directly connected to a TEMS, record the TEMS
     $nlistv_tems[$vlx] = $tems[$tx];
   }
}

# After the TNODELST NODETYPE=V data is captured, correlate data

sub fill_tnodelstv {
   #Go back and fill in the nlistv_tems
   # If the node is a managing agent, determine what the TEMS it reports to
   for ($i=0; $i<=$nlistvi; $i++) {
       next if $nlistv_tems[$i] ne "";
       my $subnode = $nlistv_thrunode[$i];
       $vlx = $nlistvx{$subnode};
       if (defined $vlx) {
          $nlistv_tems[$i] = $nlistv_thrunode[$vlx];
       }
   }

   #Go back and fill in the $magent_tems_version
   #if the agent reports to a managing agent, count the instances and also
   #record the TEMS version the managing agent connects to.
   for ($i=0; $i<=$nlistvi; $i++) {
       my $node1 = $nlistv[$i];
       $mx = $magentx{$node1};
       next if !defined $mx;
       my $mnode = $magent[$mx];
       $vlx = $nlistvx{$mnode};
       next if !defined $vlx;
       my $mthrunode = $nlistv_thrunode[$vlx];
       $tx = $temsx{$mthrunode};
       next if !defined $tx;
       $magent_tems_version[$mx] = $tems_version[$tx];
       $magent_tems[$mx] = $mthrunode;
   }

   for ($i=0; $i<=$nlistvi; $i++) {
       my $node1 = $nlistv[$i];
       $mx = $magentx{$node1};
       next if !defined $mx;
       my $mnode = $magent[$mx];
       $vlx = $nlistvx{$mnode};
       next if !defined $vlx;
       my $mthrunode = $nlistv_thrunode[$vlx];
       $tx = $temsx{$mthrunode};
       next if !defined $tx;
       $magent_tems_version[$mx] = $tems_version[$tx];
   }
}



sub new_tnodesav {
   my ($inode,$iproduct,$iversion,$io4online,$ihostaddr,$ireserved,$ithrunode,$ihostinfo,$iaffinities) = @_;

   if (substr($ihostinfo,0,4) eq "z/OS") {
      $zosagtx{$inode} = 1;
      return;
   }


   my $node_ref = $nodex{$inode};
   if (!defined $node_ref) {
      my %noderef = (
                         hostaddr => $ihostaddr,
                         product => $iproduct,
                         version => $iversion,
                         ips => {},
                      );
      $node_ref = \%noderef;
      $nodex{$inode} = \%noderef;
   }

   my $iip;

   # calculate the ip address of the duplicate agent. Some hostaddrs have port numbers and some not.
   if (index($ihostaddr,"[") != -1) {
      $ihostaddr =~ /:#(\S+)\[(\S*)\]/;
      $iip = $1 if defined $1;                # a $1 does not survive and if or else clause
   } else {
      $ihostaddr =~ /#(\S*)/;
      $iip = $1 if defined $1;
   }
   return if !defined $iip;

   $node_ref->{ips}{$iip} = 1;

   my $system_ref = $systemx{$iip};
   if (!defined $system_ref) {
      my %systemref = (
                         count => 0,                 # count of ITM agents running on the system
                         agents => [],               # array of agent running
                         osagent => "",              # if there is a OS Agent, record its name here
                         tnodesav_lines => [],       # lines from TNODESAV if present
                         dedup_lines => [],          # lines from DEDUP.CSV
                      );
      $system_ref = \%systemref;
      $systemx{$iip} = \%systemref;
   }
   $system_ref->{count} += 1;                        # count of agents on system
   push @{$system_ref->{agents}},$inode;             # add one more to the lists
   if (defined $agtosx{$iproduct}) {
      $system_ref->{osagent} = $inode;               # set os agent name if suffix is correct
      $osystemx{$iip} = $inode;                      # record ip to os agent
   }

   my $oline = "msn,";
   $oline .= $inode . ",";
   $oline .= $io4online . ",";
   $oline .= $iproduct . ",";
   $oline .= $iversion . ",";
   $oline .= $ihostaddr . ",";
   push @{$system_ref->{tnodesav_lines}},$oline;
   $tnodesav_ct += 1;
}

sub init_txt {
   my $tnodelst_fh;
   my @klst_data;
   my $inode;
   my $inodelist;
   my $inodetype;

   my $tnodesav_fh;
   my @ksav_data;
   my $io4online;
   my $iproduct;
   my $iversion;
   my $ihostaddr;
   my $ihostinfo;
   my $ireserved;
   my $ithrunode;
   my $iaffinities;

   my $ilstdate;

   open $tnodesav_fh, "<", $opt_txt_tnodesav || die("Could not open TNODESAV $opt_txt_tnodesav\n");
   @ksav_data = <$tnodesav_fh>;
   close $tnodesav_fh;
   # Get data for all TNODESAV records
   $ll = 0;
   foreach $oneline (@ksav_data) {
      $ll += 1;
      next if $ll < 5;
      chop $oneline;
      $oneline .= " " x 400;
      $inode = substr($oneline,0,32);
      $inode =~ s/\s+$//;   #trim trailing whitespace
      $io4online = substr($oneline,33,1);
      $iproduct = substr($oneline,42,2);
      $iproduct =~ s/\s+$//;   #trim trailing whitespace
      if ($io4online eq "N") {
         next if $iproduct eq "";
      }
      $iversion = substr($oneline,50,8);
      $iversion =~ s/\s+$//;   #trim trailing whitespace
      $ihostaddr = substr($oneline,59,256);
      $ihostaddr =~ s/\s+$//;   #trim trailing whitespace
      $ireserved = substr($oneline,315,64);
      $ireserved =~ s/\s+$//;   #trim trailing whitespace
      $ithrunode = substr($oneline,380,32);
      $ithrunode =~ s/\s+$//;   #trim trailing whitespace
      $ihostinfo = substr($oneline,413,16);
      $ihostinfo =~ s/\s+$//;   #trim trailing whitespace
      $iaffinities = substr($oneline,430,43);
      $iaffinities =~ s/\s+$//;   #trim trailing whitespace
      new_tnodesav($inode,$iproduct,$iversion,$io4online,$ihostaddr,$ireserved,$ithrunode,$ihostinfo,$iaffinities);
   }

   open $tnodelst_fh, "<", $opt_txt_tnodelst || die("Could not open TNODELST $opt_txt_tnodesav\n");
   @klst_data = <$tnodelst_fh>;
   close $tnodelst_fh;

   # Get data for all TNODELST type V records
   $ll = 0;
   foreach $oneline (@klst_data) {
      $ll += 1;
      next if $ll < 5;
      chop $oneline;
      $inode = substr($oneline,0,32);
      $inode =~ s/\s+$//;   #trim trailing whitespace
      $inodetype = substr($oneline,33,1);
      $inodelist = substr($oneline,42,32);
      $inodelist =~ s/\s+$//;   #trim trailing whitespace
      if ($inodelist eq "*HUB") {
         $inodetype = "V" if $inodetype eq " ";
         $inodelist = $inode;
      }
      next if $inodetype ne "V";
      $ilstdate = substr($oneline,75,16);
      $ilstdate =~ s/\s+$//;   #trim trailing whitespace
      new_tnodelstv($inodetype,$inodelist,$inode,$ilstdate);
   }
   fill_tnodelstv();
}


sub parse_lst {
  my ($lcount,$inline,$cref) = @_;            # count of desired chunks and the input line
  my @retlist = ();                     # an array of strings to return
  my $chunk = "";                       # One chunk
  my $oct = 1;                          # output chunk count
  my $rest;                             # the rest of the line to process
  $inline =~ /\]\s*(.*)/;               # skip by [NNN]  field
  $rest = " " . $1 . "        ";
  my $fixed;
  my $lenrest = length($rest);          # length of $rest string
  my $restpos = 0;                      # postion studied in the $rest string
  my $nextpos = 0;                      # floating next position in $rest string

  # KwfSQLClient logic wraps each column with a leading and trailing blank
  # simple case:  <blank>data<blank><blank>data1<blank>
  # data with embedded blank: <blank>data<blank>data<blank><data1>data1<blank>
  #     every separator is always at least two blanks, so a single blank is always embedded
  # data with trailing blank: <blank>data<blank><blank><blank>data1<blank>
  #     given the rules has to be leading or trailing blank and chose trailing on data
  # data followed by a null data item: <blank>data<blank><blank><blank><blank>
  #                                                            ||
  # data with longer then two blanks embedded must be placed on end, or handled with a cref hash.
  #
  # $restpos always points within the string, always on the blank delimiter at the end
  #
  # The %cref hash specifies chunks that are of guaranteed fixed size... passed in by caller
  while ($restpos < $lenrest) {
     $fixed = $cref->{$oct};                   #
     if (defined $fixed) {
        $chunk = substr($rest,$restpos+1,$fixed);
        push @retlist, $chunk;                 # record null data chunk
        $restpos += 2 + $fixed;
        $chunk = "";
        $oct += 1;
        next;
     }
     if ($oct >= $lcount) {                                   # handle last item
        $chunk = substr($rest,$restpos+1);
        $chunk =~ s/\s+$//;                    # strip trailing blanks
        push @retlist, $chunk;                 # record last data chunk
        last;
     }
     if ((substr($rest,$restpos,3) eq "   ") and (substr($rest,$restpos+3,1) ne " ")) {          # following null entry
        $chunk = "";
        $oct += 1;
        push @retlist, $chunk;                 # record null data chunk
        $restpos += 2;
        next;
     }
     if ((substr($rest,$restpos,2) eq "  ") and (substr($rest,$restpos+2,1) ne " ")) {            # trailing blank on previous chunk so ignore
        $restpos += 1;
        next;
     }

     $nextpos = index($rest," ",$restpos+1);
     if (substr($rest,$nextpos,2) eq "  ") {
        $chunk .= substr($rest,$restpos+1,$nextpos-$restpos-1);
        push @retlist, $chunk;                 # record new chunk
        $chunk = "";                           # prepare for new chunk
        $oct += 1;
        $restpos = $nextpos + 1;
     } else {
        $chunk .= substr($rest,$restpos+1,$nextpos-$restpos); # record new chunk fragment
        $restpos = $nextpos;
     }
  }
  return @retlist;
}

sub init_lst {
   my $tnodelst_fh;
   my @klst_data;
   my $inode;
   my $inodelist;
   my $inodetype;

   my $tnodesav_fh;
   my @ksav_data;
   my $iproduct;
   my $iversion;
   my $ihostaddr;
   my $ihostinfo;
   my $io4online;
   my $ireserved;
   my $ithrunode;
   my $iaffinities;

   my $ilstdate;

   # Parsing the KfwSQLClient output has some challenges. For example
   #      [1]  OGRP_59B815CE8A3F4403  2010  Test Group 1
   # Using the blank delimiter is OK for columns that are never blank or have no embedded blanks.
   # In this case the GRPNAME column is "Test Group 1". To manage this the SQL is arranged so
   # that a column with embedded blanks always placed at the end. The one table TSITDESC which has
   # two such columns can be retrieved with two separate SQLs.
   #

   open $tnodesav_fh, "<", $opt_lst_tnodesav || die("Could not open TNODESAV $opt_lst_tnodesav\n");
   @ksav_data = <$tnodesav_fh>;
   close $tnodesav_fh;

   # Get data for all TNODESAV records
   $ll = 0;
   foreach $oneline (@ksav_data) {
      $ll += 1;
      next if substr($oneline,0,1) ne "[";                    # Look for starting point
      chop $oneline;
      # KfwSQLClient /e "SELECT NODE,O4ONLINE,PRODUCT,VERSION,HOSTADDR,RESERVED,THRUNODE,HOSTINFO,AFFINITIES FROM O4SRV.TNODESAV" >QA1DNSAV.DB.LST
      #[1]  BNSF:TOIFVCTR2PW:VM  Y  VM  06.22.01  ip.spipe:#10.121.54.28[11853]<NM>TOIFVCTR2PW</NM>  A=00:WIX64;C=06.22.09.00:WIX64;G=06.22.09.00:WINNT;  REMOTE_catrste050bnsxa  000100000000000000000000000000000G0003yw0a7
      ($inode,$io4online,$iproduct,$iversion,$ihostaddr,$ireserved,$ithrunode,$ihostinfo,$iaffinities) = parse_lst(9,$oneline);

      $inode =~ s/\s+$//;   #trim trailing whitespace
      $iproduct =~ s/\s+$//;   #trim trailing whitespace
      $iversion =~ s/\s+$//;   #trim trailing whitespace
      $io4online =~ s/\s+$//;   #trim trailing whitespace
      $ihostaddr =~ s/\s+$//;   #trim trailing whitespace
      $ireserved =~ s/\s+$//;   #trim trailing whitespace
      $ithrunode =~ s/\s+$//;   #trim trailing whitespace
      $ihostinfo =~ s/\s+$//;   #trim trailing whitespace
      $iaffinities =~ s/\s+$//;   #trim trailing whitespace
      new_tnodesav($inode,$iproduct,$iversion,$io4online,$ihostaddr,$ireserved,$ithrunode,$ihostinfo,$iaffinities);
   }

   open $tnodelst_fh, "<", $opt_lst_tnodelst || die("Could not open TNODELST $opt_lst_tnodesav\n");
   @klst_data = <$tnodelst_fh>;
   close $tnodelst_fh;

   # Get data for all TNODELST type V records
   $ll = 0;
   foreach $oneline (@klst_data) {
      $ll += 1;
      next if substr($oneline,0,1) ne "[";                    # Look for starting point
      chop $oneline;
      # KfwSQLClient /e "SELECT NODE,NODETYPE,NODELIST,LSTDATE FROM O4SRV.TNODELST" >QA1CNODL.DB.LST
      ($inode,$inodetype,$inodelist,$ilstdate) = parse_lst(4,$oneline);
      next if $inodetype ne "V";
      new_tnodelstv($inodetype,$inodelist,$inode,$ilstdate);
   }
   fill_tnodelstv();
}
# 0.51000 - correct sleep logic
# 0.52000 - handle long hostnames
# 0.53000 - handle managing agents better
#         - make better output names
#         - handle Situation Group distributions
# 0.54000 - handle some non-OS Agent cases
