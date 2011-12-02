#!%INSTDIR%/bin/perl
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, US
#
# Generate a keypair.  Get a keysize from the user, generate
# some useful random data, generate a key, produce a CSR if
# required and add a passphrase if required.
#
# genkey.pl -- based on genkey and genkey.aux from Stronghold
#
# Mark J Cox, mjc@redhat.com and Joe Orton, jorton@redhat.com
#
# 200103 Initial version
# 200106 Converted to Newt
# 200106 Added gencert/genreq functionality
# 200106 Added some state
# 200111 Added makeca functionality
# 200305 Hide passwords entered for private key
# 200308 Adapted for Taroon
# 200308 Fix warnings in UTF-8 locale
# 200409 Added --days support
# 200804 Use NSS library for cryptography [Bug 346731]
#
#
$bindir = "%INSTDIR%/bin";
$ssltop = "%INSTDIR%/conf/ssl";
$nssconf = "/etc/httpd/conf.d/nss.conf";
$cadir = "$ssltop/CA";

use Crypt::Makerand;
use Newt;
use Getopt::Long;

sub InitRoot
{
    my $help = shift;

    Newt::Cls();
    Newt::DrawRootText(0, 0, 
		       "Red Hat Keypair Generation (c) 2008 Red Hat, Inc.");

    if ($help == 1) {
	Newt::PushHelpLine("  <Tab>/<Alt-Tab> between elements  |" .
			   "  <Space> selects  |" .
			   "  <Escape> to quit");
    }
}

sub FinishRoot
{
    Newt::PopHelpLine();
    Newt::Cls();
}

sub usage 
{
    print STDERR <<EOH;
Usage: genkey [options] servername
    --test   Test mode, faster seeding, overwrite existing key
    --genreq Generate a Certificate Signing Request (CSR)
    --makeca Generate a self-signed certificate for a CA
    --days   Days until expiry of self-signed certificate (default 30)
    --renew  CSR is for cert renewal, reusing existing key pair, openssl certs only
    --cacert Renewal is for a CA certificate, needed for openssl certs only
    --nss    Use the nss database for keys and certificates
    --gdb    For package maintainers, to trace into the nss utilities
EOH
    exit 1;
}

# Run a form with support for pressing escape and enter.
sub RunForm
{
    my ($panel, $onenter, $onescape) = @_;
    
    # set defaults
    $onenter = "Next" if (!defined($onenter));
    $onescape = "Cancel" if (!defined($onescape));    

    $panel->AddHotKey(Newt::NEWT_KEY_ESCAPE());
    $panel->AddHotKey(Newt::NEWT_KEY_ENTER()) unless $onenter eq "Ignore";

    ($reason, $data) = $panel->Run();

    if ($reason eq Newt::NEWT_EXIT_HOTKEY) {
	if ($data == Newt::NEWT_KEY_ESCAPE()) {
	    # They pressed ESCAPE; pretend they pressed "Cancel" or "No"
	    return $onescape;
	}
	elsif ($data == Newt::NEWT_KEY_ENTER()) {
	    my $current = $panel->GetCurrent();
	    if ($panel->{refs}{$$current}->Tag()) {
		# They pressed ENTER over a button; pretend they pressed it.
		return $panel->{refs}{$$current}->Tag();
	    }
	    return $onenter;
	}
    }
    elsif ($reason eq Newt::NEWT_EXIT_COMPONENT) {
	return $data->Tag();
    }
    die "unhandled event ", $reason, " ", $data, "\n";
}

#
# main
#

my $test_mode = '';
my $genreq_mode = '';
my $ca_mode = '';
my $cert_days = 30;
my $nss ='';
my $renew = '';
my $cacert = '';
my $modNssDbDir = '';
my $nssNickname = '';
my $nssDBPrefix = '';
my $gdb = '';
GetOptions('test|t' => \$test_mode, 
           'genreq' => \$genreq_mode,
           'days=i' => \$cert_days,
           'renew'  => \$renew,
           'cacert' => \$cacert,
           'nss|n'  => \$nss,
           'gdb'    => \$gdb,
           'makeca' => \$ca_mode) or usage();
usage() unless @ARGV != 0;

if ($genreq_mode && $renew && !$nss) {
print STDERR <<EOH;
Certificate renewal from PEM files is not yet supported.
EOH
}

$skip_random = $test_mode;
$overwrite_key = $test_mode;
$servername = $ARGV[0];
$randfile = $ssltop."/.rand.".$$;
$keyEncPassword = '';  # for the one we write
$tmpPasswordFile = ''; # none has been created yet
$keyfile = $ssltop."/private/".$servername.".key";
if ($ca_mode) {
    $keyfile = $cadir."/private/".$servername.".key";
}

### State variables
my $bits = 0;
my $myca = "Other";
my $useca = 0;
my $subject;
#

Newt::Init();
InitRoot(1);

local $SIG{__DIE__} = sub { @err=@_; Newt::Finished(); die @err;};

# Either mod_nss or mod_ssl is required
requireModule();

# For mod_nss we need these variables set
if ($nss) {
    # the configuration file is required
    if (!nssconfigFound()) {
        Newt::newtWinMessage("Error", "Close", 
        "Could not find mod_nss's nss.conf file".
        "for this host:\n\nPress return to exit");
        Newt::Finished();
        exit 1;
    }
    
    $modNssDbDir = getModNSSDatabase();
    $nssNickname = $servername ? $servername : getNSSNickname();
    $nssDBPrefix = getNSSDBPrefix();
}

#
# Does the key already exist? don't overwrite
#

if (!$nss) {
    if (!$genreq_mode && -f $keyfile && !$overwrite_key) {
        Newt::newtWinMessage("Error", "Close", 
		"You already have a key file for this host in file:\n\n" .
		$keyfile . "\n\n" .
		"This script will not overwrite an existing key.\n" . 
		"You will need to remove or rename this file in order to" .
		"generate a new key for this host, then rerun the command");
        Newt::Finished();
        exit 1;
    }
} else {
    # check for the key in the database
    if (!$genreq_mode && keyInDatabase($nssNickname,$modNssDbDir) &&
        !$renew && !$overwrite_key) {
        Newt::newtWinMessage("Error", "Close", 
		    "You already have a key file for this host in the datatabase:\n\n" .
		    "$modNssDbDir" ." with nickname ". "$nssNickname" . "\n\n" .
		    "This script will not overwrite an existing key.\n" . 
		    "You will need to remove or rename the database in order to" .
		    "generate a new key for this host, then rerun the command");
        Newt::Finished();
       exit 1;
    }
}

######################################################################
# Main
#

# Array of windows which we cycle through. Each window function should
# return: 
#   "Next" or "Skip" -> go on to the next window
#   "Back" -> go back to the last window which returned "Next"
#   "Cancel" -> cancelled: quit and return failure.
#
# "Skip" is to allow for windows which don't display anything (due
# to choices made in previous windows, for instance).
#
my @windows;
if ($genreq_mode) {
    $useca = 1;
    @windows = $renew 
        ? (passwordWindow,genReqWindow,) 
        : (getkeysizeWindow,
           customKeySizeWindow,
           getRandomDataWindow,
           passwordWindow,
           genReqWindow,
           );
    $doingwhat="CSR generation";
} elsif ($ca_mode) {
    @windows = (CAwelcomeWindow,
		getkeysizeWindow,
		customKeySizeWindow,
		getRandomDataWindow,
		passwordWindow,
		genCACertWindow,
		);
    $doingwhat="CA cert generation";
} else {
    @windows = (welcomeWindow,
		getkeysizeWindow,
		customKeySizeWindow,
		getRandomDataWindow,
		wantCAWindow,
		passwordWindow,
		genReqWindow,
        genCertWindow,
        ### @EXTRA@ ### Leave this comment here.
        );
    $doingwhat="testing CSR and cert generation";
}

my $screen = 0;

my @screenstack;

my $result;

while ($screen <= $#windows) {
    $result = $windows[$screen]->();
    print STDERR "undef from window #" .$screen . "\n" if (!$result);
    if ($result eq "Cancel") {
	my $panel = Newt::Panel(1, 2, "Confirm");

	$panel->Add(0, 0, 
		  Newt::TextboxReflowed(60, 10, 10, 0, 
					"Do you want to cancel ".$doingwhat.
					"?"));

	$panel->Add(0, 1, DoubleButton("Yes", "No"));
	# Default to NOT cancel if escape is pressed (again)
	$ret = &RunForm($panel, "No", "No");

	$panel->Hide();
	undef $panel;

	last if $ret eq "Yes";
	next;
    }

    $nextscreen = $screen + 1 if ($result eq "Next" or $result eq "Skip"
				  or !$result);
    $nextscreen = pop @screenstack if ($result eq "Back" and scalar(@screenstack));
    push @screenstack, $screen if ($result eq "Next");
    $screen = $nextscreen;
}

# Exit
clearSensitiveData();
Newt::Finished();
exit 1 if ($result eq "Cancel");
exit 0;

#
# end main
#

######################################################################
# Handy functions

# Returns a panel containing two buttons of given names.
sub DoubleButton {
    my ($left, $right) = @_;
    
    my $leftb = Newt::Button($left)->Tag($left);
    my $rightb = Newt::Button($right)->Tag($right);

    Newt::Panel(2, 1)
      ->Add(0, 0, $leftb, Newt::NEWT_ANCHOR_RIGHT(), 0, 1, 0, 0)
	  ->Add(1, 0, $rightb, Newt::NEWT_ANCHOR_LEFT(), 1, 1, 0, 0);
}

# Returns a panel containing next/back/cancel buttons.
sub NextBackCancelButton {
    
    my $nextb = Newt::Button('Next')->Tag('Next');
    my $backb = Newt::Button('Back')->Tag('Back');
    my $cancelb = Newt::Button('Cancel')->Tag('Cancel');

    Newt::Panel(3, 1)
      ->Add(0, 0, $nextb, Newt::NEWT_ANCHOR_RIGHT(), 0, 1, 0, 0)
	  ->Add(1, 0, $backb, Newt::NEWT_ANCHOR_RIGHT(), 1, 1, 0, 0)
	      ->Add(2, 0, $cancelb, Newt::NEWT_ANCHOR_LEFT(), 1, 1, 0, 0);
}

# Require that this Apache module (mod_nss or mod_ssl) be installed
sub requireModule {

    my $module = $nss ? "mod_nss" : "mod_ssl";	
    my $not_installed_msg = `rpm -q $module | grep "not installed"`;
	
	if ($not_installed_msg) {
        Newt::newtWinMessage("Error", "Close", 
        "$not_installed_msg".
        "\nIt is required to generate this type of CSRs or certs".
        "for this host:\n\nPress return to exit");
        Newt::Finished();
        exit 1;
    }	
}

# Check that nss.conf exists
sub nssconfigFound {
    # if it isn't in its usual place
    if (!$nssconf || !(-f $nssconf)) {
        # do an rpm query
        my $cmd = 'rpm -ql mod_nss';
        my $tmplist = "list";
        system("$cmd > $tmplist");
        $nssconf = `grep nss.conf $tmplist`;
        unlink($tmplist);
    }
    return ($nssconf && (-f $nssconf));
}

# Returns the mod_nss database directory path.
sub getModNSSDatabase {
   
    # Extract the value from the mod_nss configuration file.
    my $cmd ='/usr/bin/gawk \'/^NSSCertificateDatabase/ { print $2 }\'' . " $nssconf"; 
    my $dbfile = "dbdirectory";
    system("$cmd > $dbfile");
    open(DIR, "<$dbfile");
    my $dbdir = '';
    chomp($dbdir = <DIR>);
    
    unlink($dbfile);
    
    return $dbdir;
}

# Returns the rsa server name.
sub getNSSNickname {

    # Extract the value from the mod_nss configuration file.
    my $cmd ='/usr/bin/gawk \'/^NSSNickname/ { print $2 }\'' . " $nssconf";
    my $nicknamefile = "nssnickname";
    system("$cmd > $nicknamefile");
    open(NICK, "<$nicknamefile");  
    my $nickname = ''; 
    chomp($nickname = <NICK>); 
    unlink($nicknamefile);
    return $nickname;
}

# Returns the nss database prefix
sub getNSSDBPrefix {

    # Extract the value from the mod_nss configuration file.
    my $cmd ='/usr/bin/gawk \'/^NSSDBPrefix/ { print $2 }\'' . " $nssconf";
    my $prefixfile = "dbprefix";
    system("$cmd > $prefixfile");
    open(PREFIX, "<$prefixfile");
    my $prefix = '';
    chomp($prefix = <PREFIX>); 
    unlink($prefixfile);

    return $prefix;
}

# Erases and deletes the password file
sub clearSensitiveData {
    if (-f $tmpPasswordFile) {
       open(DOOMED,$tmpPasswordFile);
       truncate(DOOMED,0);
       close(DOOMED);
       unlink($tmpPasswordFile);
    }
}

# Remove a directory and its contents
sub removeDirectory {
    my ($dir) = @_;
    if (-f $dir) {
        opendir(DOOMED, $dir) || die("Cannot open directory");
        my @thefiles= readdir(DOOMED);
        foreach my $file (@thefiles) {
            unlink @file;
        }
        closedir(DOOMED);
    	rmdir $dir;
    }
}

# Print error message
sub printError {
    my ($msg) = @_;
    Newt::Suspend();
    print STDERR "$msg\n";
    Newt::Resume();
}

# Is the given key in the database?
sub keyInDatabase {
    my ($nickname, $dbdir) = @_;
    my $tmp = "tmp";
    my $answer = `$bindir/certutil -L -d $dbdir | grep $nickname`;
    return $answer;
}

######################################################################
# The window functions

sub makerand
{
    require Fcntl;

    my ($bits,$filename) = @_;

    my $count = 0;
    
    my @credits = ("This software contains the truerand library",
		   "developed by Matt Blaze, Jim Reeds, and Jack",
		   "Lacy. Copyright (c) 1992, 1994 AT&T.");
    my ($cols, $rows) = Newt::GetScreenSize();
    
    foreach (@credits) {
	$count++;
	Newt::DrawRootText($cols-45, $rows-5 + $count, $_);
    }

    $count = 0;
    
    my $panel = Newt::Panel(1, 2, "Generating random bits");
    my $scale = Newt::Scale(40, $bits);

    $panel->Add(0, 0, Newt::Label("(this may take some time)"));

    $panel->Add(0, 1, $scale, 0, 0, 1);
		
    $panel->Draw();
    
    if (!sysopen($randfh,$filename,Fcntl::O_WRONLY()|Fcntl::O_CREAT()
		 |Fcntl::O_TRUNC()|Fcntl::O_EXCL(),0600)) {
	Newt::newtWinMessage("Error", "Close", 
			     "Can't create random data file");
	$panel->Hide();
	undef $panel;
	return "Cancel";
    }

    Newt::Refresh();
    while ($count++ < $bits/32) { 
        use bytes; # random data is not UTF-8, prevent warnings
	# decode as an "native-length" unsigned long
	syswrite($randfh,pack("L!",Crypt::Makerand::trand32()));
	$scale->Set($count*32);
	Newt::Refresh();
    }
    $panel->Hide();
    undef $panel;
    close $randfh;
}

sub getkeysizeWindow()
{
    $minbits = 512;
    $maxbits = 8192;

    my $title= <<EOT;
Choose the size of your key. The smaller the key you choose the faster
your server response will be, but you'll have less security. Keys of
less than 1024 bits are easily cracked.  Keys greater than 1024 bits
don't work with all currently available browsers. 

We suggest you select the default, 1024 bits
EOT
    my $panel = Newt::Panel(1, 3, "Choose key size");
    my $listbox = Newt::Listbox(5, 0);
    my $text = Newt::Textbox(70, 6, 0, $title);
    my @listitems = ("512 (insecure)",
		     "1024 (medium-grade, fast speed) [RECOMMENDED]",
		     "2048 (high-security, medium speed)",
		     "4096 (paranoid-security, tortoise speed)",
		     "Choose your own");

    $listbox->Append(@listitems);
    
    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, $listbox, 0, 0, 1);
    $panel->Add(0, 2, NextBackCancelButton());
    
    Newt::newtListboxSetCurrent($listbox->{co}, 1);

    $panel->Draw();

    $ret = &RunForm($panel);    

    if ($ret eq "Cancel" or $ret eq "Back") {
	$panel->Hide();
	undef $panel;
	return $ret;
    }
    
    $bits = 256;

    foreach $item(@listitems) {
	$bits = $bits * 2;
	if ($item eq $listbox->Get()) {
	    last;
	}
    }

    $panel->Hide();
    undef $panel;
    return $ret;
}

sub customKeySizeWindow()
{
    return "Next" if $bits < 8192; # else, choose custom size.

    Newt::Refresh();
    
    $bits = 0;

    $title = <<EOT;
Select the exact key size you want to use. Note that some browsers do
not work correctly with arbitrary key sizes. For maximum compatibility
you should use 512 or 1024, and for a reasonable level of security you
should use 1024.
EOT

    $panel = Newt::Panel(1, 3, "Select exact key size");
    my $entry = Newt::Entry(10, 0, "");

    $panel->Add(0, 0, Newt::Textbox(70, 4, 0, $title));
    $panel->Add(0, 1, $entry);
    $panel->Add(0, 2, NextBackCancelButton());
    
    do {
	$panel->Focus($entry);

	$ret = &RunForm($panel);

	if ($ret eq "Cancel" or $ret eq "Back") {
	    $panel->Hide();
	    undef $panel;
	    return $ret;
	}

	if ($entry->Get() ne "") {
	    $bits = int($entry->Get());
	} else {
	    $bits = 0;
	}
    } while ($bits < $minbits || $bits > $maxbits);
    
    $panel->Hide();
    undef $panel;

    return "Next";
}

sub welcomeWindow()
{
    my $name = $servername;
    my $where_key = $nss
        ? $modNssDbDir."/$nssDBPrefix"."key3.db" : "$ssltop/private/$name.key";
    my $where_cert = $nss
        ? $modNssDbDir."/$nssDBPrefix"."cert8.db" : "$ssltop/certs/$name.crt";
    my $what = $nss ? "directory" : "file";
    my $message = <<EOT;
You are now generating a new keypair which will be used to encrypt all
SSL traffic to the server named $name. 
Optionally you can also create a certificate request and send it to a
certificate authority (CA) for signing.

The key will be stored in 
    $where_key
The certificate stored in 
    $where_cert

If the key generation fails, move the $what
    $where_key 
to a backup location and try again.
EOT

    my $panel = Newt::Panel(1, 2, "Keypair generation");
    my $text = Newt::Textbox(70, 10, Newt::NEWT_TEXTBOX_SCROLL(), $message);
    my $ret;

    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, DoubleButton("Next","Cancel"));

    $ret = &RunForm($panel);

    $panel->Hide();
    undef $panel;

    return $ret;
}

sub CAwelcomeWindow()
{
    my $name = $servername;
    my $where = $nss ? $modNssDbDir."/$nssDBPrefix"."key3.db" : "$cadir/private/$name"; 
    my $message = <<EOT;
You are now generating a new keypair which will be used for your
private CA

The key will be stored in 
    $where

If the key generation fails, move the file 
    $where
to a backup location and try again.
EOT

    my $panel = Newt::Panel(1, 2, "CA Key generation");
    my $text = Newt::Textbox(70, 10, Newt::NEWT_TEXTBOX_SCROLL(), $message);
    my $ret;

    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, DoubleButton("Next","Cancel"));

    $ret = &RunForm($panel);

    $panel->Hide();
    undef $panel;

    return $ret;
}

sub wantCAWindow
{
    my $panel = Newt::Panel(1, 2, "Generate CSR");

    $panel->Add(0, 0, 
	      Newt::TextboxReflowed(60, 10, 10, 0, 
				    "Would you like to send a Certificate Request (CSR) " .
				    "to a Certificate Authority (CA)?"));

    $panel->Add(0, 1, DoubleButton("Yes", "No"));

    $ret = &RunForm($panel);

    $panel->Hide();
    undef $panel;

    if ($ret eq "Cancel") {
	return "Cancel";
    }

    $useca = ($ret eq "Yes") ? 1 : 0;

    return "Next";
}

# Save the passphrase to a temporary file.
sub savePassword 
{
    my ($passwd) = @_;
    #
    # Write password to a file with lines formatted as:
    # NSS Certificate DB:access_passphrase
    # PEM Token #0:ca_key_access_passphrase
    # PEM Token #1:server_key_access_passphrase
    #
    my $passwordLine = $nss
        ? "NSS Certificate DB" : $cacert ? "PEM Token #0:" : "PEM Token #1:";
    $passwordLine .= "$passwd\n";
    if ($tmpPasswordFile) {
        # append to existing file
        if (!open(SESAME, ">>$tmpPasswordFile")) {
            Newt::newtWinMessage("Error", "Close",
                "Unable to append passphrase to $tmpPasswordFile".
			    "\n\nPress return to continue");
	        return "Back";
        }
    } else {
        # write to a new file
        $tmpPasswordFile = ".passwordfile.".$$;
        if (!open (SESAME, ">$tmpPasswordFile")) {
            Newt::newtWinMessage("Error", "Close",
                "Unable to save passphrase to $tmpPasswordFile".
			    "\n\nPress return to continue");
		    $tmpPasswordFile = ''; # mark it as never created
	        return "Back";
        }
    }
    print SESAME $passwordLine;
    close(SESAME);
    # This file will be deleted on program exit.

    return "Next";
}

# Prompts for a module or key access password.
# The argument indicates wheter the password is to
# access the nss module access or for access to the key
# to be loaded from a pem file into a PEM module token.
sub moduleAccesPasswordWindow
{
    my ($what) = @_;
    # either "module" or "key"

    my $message = <<EOT;
At this stage you can provide the $what acess passphrase.
EOT
    $panel = Newt::Panel(1, 3, $what." access");
    $panel->Add(0, 0, Newt::Textbox(70, 5, 0, $message));

    my $checkbox = Newt::Checkbox($what." access password if any");
    $panel->Add(0, 1, $checkbox);
    $panel->Add(0, 2, NextBackCancelButton());

    $ret = &RunForm($panel);

    my $plain = 1;
    $plain = 0 if $checkbox->Checked();

    $panel->Hide();
    undef $panel;

    return $ret if ($ret eq "Back" or $ret eq "Cancel" or $plain == 1);
 
    $panel = Newt::Panel(1, 3, "Enter the $what passphrase");

    $message = <<EOT;
This is the passphrase to your $what.
EOT
    $panel->Add(0, 0, Newt::Textbox(70, 5, 0, $message));
    $subp = Newt::Panel(2,2);
    $entp1 = AddField($subp,0,"Passphrase","",30,0,
                      Newt::NEWT_FLAG_HIDDEN());

    $panel->Add(0, 1, $subp, 0, 0, 1);
    $panel->Add(0, 2, NextBackCancelButton());

    while (1) {
        # Clear the password entry box to avoid confusion on looping
        $entp1->Set("");
	    $panel->Focus($entp1);

	    # Pass "Ignore" to make enter go to next widget.
	    $ret = &RunForm($panel, "Ignore");

	    if ($ret eq "Cancel" or $ret eq "Back") {
	        $panel->Hide();
	        undef $subp;
	        undef $panel;
	        return $ret;
	    }
	    $pass1 = $entp1->Get();

	    last;
    }

    $panel->Hide();
    undef $panel;

    return $ret if ($ret eq "Back" or $ret eq "Cancel");

    # Save it to a temporary file to supply to the nss utilities,
    # the file will be erased upon exit
    savePassword($pass1);

    return "Next";
	
}

# Prompts for key encryption password 
# When using NSS it prompts for the
# module acces password instead.
sub passwordWindow
{
    if ($nss || $renew) {
        # nss module access password or key password
        return moduleAccesPasswordWindow($nss ? "module" : "key");
    }
	
    my $message = <<EOT;
At this stage you can set the passphrase on your private key. If you
set the passphrase you will have to enter it every time the server
starts.  The passphrase you use to encrypt your key must be the same
for all the keys used by the same server installation.

If you do not encrypt your key, then if someone breaks into your
server and grabs the file containing your key, they will be able to
decrypt all communications to and from the server that were negotiated
using that key. If your key is encrypted it would be much more
work for someone to retrieve the private key.
EOT
    $panel = Newt::Panel(1, 3, "Protecting your private key");

    $panel->Add(0, 0, Newt::Textbox(70, 11, 0, $message));

    my $checkbox = Newt::Checkbox("Encrypt the private key");
    $panel->Add(0, 1, $checkbox);

    $panel->Add(0, 2, NextBackCancelButton());

    $ret = &RunForm($panel);

    my $plain = 1;
    $plain = 0 if $checkbox->Checked();

    $panel->Hide();
    undef $panel;

    return $ret if ($ret eq "Back" or $ret eq "Cancel" or $plain == 1);
 
    $panel = Newt::Panel(1, 3, "Set private key passphrase");

    $message = <<EOT;
Now we are going to set the passphrase on the private key. This
passphrase is used to encrypt your private key when it is stored
on disk. You will have to type this passphrase when the server
starts.

-- DO NOT LOSE THIS PASS PHRASE --

If you lose the pass phrase you will not be able to run the server
with this private key. You will need to generate a new private/public
key pair and request a new certificate from your certificate authority.
EOT
    $panel->Add(0, 0, Newt::Textbox(70, 11, 0, $message));
    $subp = Newt::Panel(2,2);
    $entp1 = AddField($subp,0,"Passphrase (>4 characters)","",30,0,
                      Newt::NEWT_FLAG_HIDDEN());
    $entp2 = AddField($subp,1,"Passphrase (again)        ","",30,0,
                      Newt::NEWT_FLAG_HIDDEN());

    $panel->Add(0, 1, $subp, 0, 0, 1);
    $panel->Add(0, 2, NextBackCancelButton());

    while (1) {
        # Clear the password entry boxes to avoid confusion on looping
        $entp1->Set("");
        $entp2->Set("");

	$panel->Focus($entp1);

	# Pass "Ignore" to make enter go to next widget.
	$ret = &RunForm($panel, "Ignore");

	if ($ret eq "Cancel" or $ret eq "Back") {
	    $panel->Hide();
	    undef $subp;
	    undef $panel;
	    return $ret;
	}
	$pass1 = $entp1->Get();
	$pass2 = $entp2->Get();

	if ($pass1 ne $pass2) {
	    Newt::newtWinMessage("Error", "Close",
                                 "The passphrases you entered do not match.");
	    next;
	}
	if (length($pass1)<4) {
	    Newt::newtWinMessage("Error", "Close",
			       "The passphrase must be at least 4 characters".
			       "\n\nPress return to try again");
	    next;
	}
	last;
    }

    $panel->Hide();
    undef $panel;

    return $ret if ($ret eq "Back" or $ret eq "Cancel");

    $keyEncPassword = $pass1;

    return "Next";
}

#
# Bottleneck routine to call the nss utilities.
# Calls are bracketed by newt suspend and resume
# enabling user interaction from the nss utilities
# and trace messages to the console.
#
sub nssUtilCmd {
    
    my ($cmd, $args) = @_;

    Newt::Suspend();
    print STDOUT "$cmd $args"."\n";
    $! = '';
    if ($gdb) {
        system("gdb $cmd");
    } else {
        system("$cmd $args");
        print STDERR "$cmd returned $!"."\n" if $!;
    }
    Newt::Resume();
}

#
# make a certificate using the database
#
sub makeCertNSS
{
    my ($certfile, # output
        $subject, $days, $nickname,
        $noisefile, $pwdfile) = @_;
    
    # If no days specified it's a ca so use 2 years
    use integer;
    my $months = $days / 30;      
    my $trustargs = $ca_mode ? "CT,," : "u,,";
    $trustargs = "\"" . $trustargs. "\"";
    
    my $args = "-S ";
    $args .= "-n $nickname ";
    $args .= "-s $subject "; 
    $args .= "-x ";              ## self-signed
    $args .= "-t $trustargs ";
    $args .= "-k rsa ";
    $args .= "-g $bits ";
    $args .= "-v $months ";
    $args .= "-a ";
    $args .= "-f $pwdfile " if $pwdfile;
    $args .= "-z $noisefile " if $noisefile;
    $args .= "-d $modNssDbDir "; 
    $args .= "-p $nssDBPrefix " if $nssDBPrefix;
    $args .= "-o $certfile " if $certfile;
    
    nssUtilCmd("$bindir/certutil", $args);

    unlink($noisefile);
    
    if ($certfile && !-f $certfile) {
        Newt::newtWinMessage("Error", "Close", 
			     "Was not able to create a certificate for this ".
			     "host:\n\nPress return to exit");
        Newt::Finished();
        exit 1;
    }
}

# Create a certificate-signing request file that can be submitted to 
# a Certificate Authority for processing into a finished certificate.
sub genRequestNSS 
{
    my ($csrfile, # output
        $subject, $days, $noisefile, $pwdfile) = @_;
    
    use integer;
    my $months = $days / 30;
    
    my $args = "-R ";
    
    $args .= "-s $subject ";
    $args .= "-d $modNssDbDir ";
    $args .= "-p $nssDBPrefix " if $nssDDPrefix;
    $args .= "-a ";              ## using ascii 
    $args .= "-k rsa ";
    $args .= "-g $bits ";
    $args .= "-f $pwdfile "   if $pwdfile;
    $args .= "-v $months ";
    $args .= "-z $noisefile " if $noisefile;
    $args .= "-o $csrfile ";
    
    nssUtilCmd("$bindir/certutil", $args);

    unlink($noisefile);
    
    if (!-f $csrfile) {
        Newt::newtWinMessage("Error", "Close", 
                 "Was not able to create a CSR for this ".
                 "host:\n\nPress return to exit");
        Newt::Finished();
        exit 1; 
    }
}

# Generate a CA certificate file.
# Use keyutil which supports exporting the key.
sub makeCertOpenSSL
{
    my ($keyfile, $certfile, # output
        $subject, $days, $noisefile, $pwdfile) = @_;

    use integer;
    my $months = $days ? $days / 30 : 24;

    # build the arguments for a gen cert call, self-signed
    my $args = "-c makecert ";
    $args   .= "-g $bits ";
    $args   .= "-s $subject ";
    $args   .= "-v $months "; 
    $args   .= "-a ";              ## using ascii 
    $args   .= "-z $noisefile " if $noisefile;
    $args   .= "-e $keyEncPassword " if $keyEncPassword; 
              # there is no password when the
              # user wants the key in the clear
    $args   .= "-o $certfile ";
    $args   .= "-k $keyfile";

    nssUtilCmd("$bindir/keyutil", $args);    

    if (!-f $certfile) {
        Newt::newtWinMessage("Error", "Close", 
                 "Was not able to create a certificate for this ".
                 "host:\n\nPress return to exit");
        unlink($noisefile);
        Newt::Finished();
        exit 1;
    }
    if ($keyfile && (-f $keyfile)) {
        if (chmod(0400, $keyfile) != 1) {
            Newt::newtWinMessage("Error", "Close",
                             "Could not set permissions of private key file.\n".
                             "$keyfile");
           Newt::Finished();
           unlink($noisefile);
           exit 1;
        }
    }
    unlink($noisefile);
}

# Create a certificate-signing request file that can be submitted to a 
# Certificate Authority (CA) for processing into a finished certificate.
# Use keyutil which exports key.
sub genRequestOpenSSL
{
    my ($keyfile,$csrfile, # output
        $subject,$days,$noisefile,$pwdfile) = @_;

    use integer;
    my $months = $days ? $days / 30 : 24;
    
    # build the arguments for a gen request call
    my $args = "-c genreq ";
    $args   .= "-g $bits "; 
    $args   .= "-s $subject ";
    $args   .= "-v $months ";
    $args   .= "-a ";              ## using ascii
    $args   .= "-o $csrfile ";
    $args   .= "-k $keyfile "; 
    $args   .= "-e $keyEncPassword " if $keyEncPassword;
              # there is no password when the
              # user wants the key in the clear
    $args   .= "-z $noisefile "  if $noisefile;
 
    nssUtilCmd("$bindir/keyutil", $args);
         
    unlink($noisefile);
    Newt::Resume();
    
    if (!-f $csrfile) {
        Newt::newtWinMessage("Error", "Close", 
                 "Unable to create a cert signing request for this ".
                 "host:\n\nPress return to exit");
        Newt::Finished();
        exit 1;
    }
    if ($keyfile && !(-f $keyfile)) {
        Newt::newtWinMessage("Error", "Close", 
                 "Unable to create a key for this ".
                 "host:\n\nPress return to exit");
        Newt::Finished();
        exit 1;
    }
    if (chmod(0400, $keyfile) != 1) {
        Newt::newtWinMessage("Error", "Close",
                 "Could not set permissions of private key file.\n".
                 "$keyfile");
        Newt::Finished();
        exit 1;
    }
}

# Renew a certificate which is stored in the nss database
sub renewCertNSS
{
    my ($csrfile, $dbdir, $dbprefix, $nickname, $days, $pwdfile) = @_;

    use integer;
    my $months = $days ? $days / 30 : 24;
    
    # Build the arguments for a certificate renewal request
    # This is a request where we reuse the existing key pair
    
    my $args = "-R ";
    $args   .= "-d $dbdir ";
    $args   .= "-p $dbprefix " if $dbprefix;
    $args   .= "-a ";              ## using ascii 
    $args   .= "-k $nickname ";    ## pass cert nickname as key id
    $args   .= "-f $pwdfile "   if $pwdfile;
    $args   .= "-v $months ";
    $args   .= "-o $csrfile ";
    
    nssUtilCmd("$bindir/certutil", $args);
    
    if (!-f $csrfile) {
        Newt::newtWinMessage("Error", "Close", 
                 "Was not able to create a CSR for this ".
                 "host:\n\nPress return to exit");
        Newt::Finished();
        exit 1; 
    }
}

# Renew a certificate which is stored in a PEM file
sub renewCertOpenSSL
{
    my ($csrfile, # output
        $certfile,$keyfile,$cacert,$days) = @_;

    use integer;
    my $months = $days ? $days / 30 : 24;
    
    # Build the arguments for a certificate renewal request
    # This is a request where we reuse the existing key pair

    my $args = "--command genreq ";
    $args   .= "--ascii ";              ## using ascii
    $args   .= "--renew $certfile "; 
    $args   .= "--input $keyfile "; 
    $args   .= "--cacert " if $cacert;
    $args   .= "--filepwdnss $pwdfile " if $pwdfile;    
    $args   .= "--validity $months "; 
    $args   .= "--out $csrfile ";
 
    nssUtilCmd("$bindir/keyutil", $args);
         
    unlink($noisefile);
    Newt::Resume();
    
    if (!-f $csrfile) {
        Newt::newtWinMessage("Error", "Close", 
                 "Unable to create a cert signing request for this ".
                 "host:\n\nPress return to exit");
        Newt::Finished();
        exit 1;
    }
}

sub AddField
{
    my ($panel, $row, $msg, $default, $width, $topspace, $flags) = (@_, 0, 0);
    my $entry;

    $panel->Add(0, $row, Newt::Label($msg), Newt::NEWT_ANCHOR_RIGHT(), 0, $topspace);
    $entry = Newt::Entry($width, $flags, $default);
    $panel->Add(1, $row, $entry, Newt::NEWT_ANCHOR_LEFT(), 1, $topspace);

    $entry;
}

sub getCertDetails
{
    my ($fqdn, $msg, $iscsr) = (@_, 0);
    my $cert;
    my $panel;
    my $subp;

    my $ents = {}, $cert = {};

    $panel = Newt::Panel(1, 3, "Enter details for your certificate");

    $panel->Add(0, 0, Newt::TextboxReflowed(65, 10, 10, 0, $msg));
    
    if ($iscsr) {
	$subp = Newt::Panel(2, 9);
    } else {
	$subp = Newt::Panel(2, 6);
    }

    $ents{'C'} = AddField($subp, 0, "Country Name (ISO 2 letter code)", "GB", 3);
    $ents{'ST'} = AddField($subp, 1, 
			   "State or Province Name (full name)", "Berkshire", 20, 0,
			  Newt::NEWT_ENTRY_SCROLL());
    $ents{'L'} = AddField($subp, 2, "Locality Name (e.g. city)", "Newbury", 20, 0, 
			  Newt::NEWT_ENTRY_SCROLL());
    $ents{'O'} = AddField($subp, 3, 
			  "Organization Name (eg, company)", "My Company Ltd", 30, 0,
			  Newt::NEWT_ENTRY_SCROLL());
    $ents{'OU'} = AddField($subp, 4, "Organizational Unit Name (eg, section)", "", 30, 0,
			   Newt::NEWT_ENTRY_SCROLL());
    $ents{'CN'} = AddField($subp, 5, 
			   "Common Name (fully qualified domain name)", $fqdn, 30, 1, 
			   Newt::NEWT_ENTRY_SCROLL());

    if ($iscsr) {

	my $msg = "Extra attributes for certificate request:";

	$subp->Add(0, 6, Newt::Textbox(length($msg), 1, 0, $msg),
		   Newt::NEWT_ANCHOR_RIGHT());

	$ents{'Challenge'} = AddField($subp, 7, "Optional challenge password",
				      "", 20, 0);
	$ents{'CompanyName'} = AddField($subp, 8, "Optional company name", "", 30, 0,
			  Newt::NEWT_ENTRY_SCROLL());
    }

    $panel->Add(0, 1, $subp, 0, 0, 1);

    $panel->Add(0, 2, NextBackCancelButton(), 0, 0, 0, 0, -1);

    while (1) {
	
	# Pass "Ignore" to make enter go to next widget.
	$ret = &RunForm($panel, "Ignore");

	if ($ret eq "Next" && $iscsr) {
	    my $pass = $ents{'Challenge'}->Get();
	    if (length($pass) > 0 && length($pass) < 4) {
		Newt::newtWinMessage("Error", "Retry",
				     "The challenge password must be at least four characters in length");
		# Move focus to challenge password field
		$panel->Focus($ents{'Challenge'});
		# and go again.
		next;
	    }
	}
	last;
    }

    if ($ret eq "Cancel" or $ret eq "Back") {
	$panel->Hide();
	undef $subp;
	undef $panel;
	return $ret;
    }

    $cert{'C'} = $ents{'C'}->Get();
    $cert{'ST'} = $ents{'ST'}->Get();
    $cert{'L'} = $ents{'L'}->Get();
    $cert{'O'} = $ents{'O'}->Get();
    $cert{'OU'} = $ents{'OU'}->Get();
    $cert{'CN'} = $ents{'CN'}->Get();

    # Build the subject from the details
    
    $SEP     = ", ";
    $subject = 'CN' . "=" . $cert{'CN'};
    $subject = $subject . $SEP . 'OU' . "=" . $cert{'OU'} if $cert{'OU'};
    $subject = $subject . $SEP . 'O'  . "=" . $cert{'O'}  if $cert{'O'};
    $subject = $subject . $SEP . 'L'  . "=" . $cert{'L'}  if $cert{'L'};
    $subject = $subject . $SEP . 'ST' . "=" . $cert{'ST'} if $cert{'ST'};
    $subject = $subject . $SEP . 'C'  . "=" . $cert{'C'}  if $cert{'C'};
    
    if ($iscsr) {
    $cert{'CompanyName'} = $ents{'CompanyName'}->Get();
    $cert{'Challenge'} = $ents{'Challenge'}->Get();
    $subject = $subject . $SEP . 'CompanyName' ."=" . $cert{'CompanyName'} if $cert{'CompanyName'};
    $subject = $subject . $SEP . 'Challenge' ."=" . $cert{'Challenge'} if $cert{'Challenge'};
    }

    $panel->Hide();

    undef $subp;
    undef $panel;

    # must escape the double quotes because
    # it will be embedded in another string
    $subject = "\"" . "$subject" . "\"";
	
    return "Next";
}

sub whichCAWindow {
    return "Skip" unless $useca;

    my $title = <<EOT;
Please choose the Certificate Authority you wish to send
your certificate request to
EOT
    my $panel = Newt::Panel(1, 3, "Choose Certificate Authority");
    my $listbox = Newt::Listbox(4, 0);
    my $text = Newt::Textbox(60, 2, 0, $title);
    my @listitems = ("Equifax","Thawte","VeriSign","Other");
    undef $myca;

    $listbox->Append(@listitems);
    
    $panel->Add(0, 0, $text);
    $panel->Add(0, 1, $listbox, 0, 0, 1);
    if ($genreq_mode) {
	$panel->Add(0, 2, DoubleButton("Next","Cancel"));
    } else {
	$panel->Add(0, 2, NextBackCancelButton());
    }

    Newt::newtListboxSetCurrent($listbox->{co}, 0);

    $panel->Draw();
    $ret = &RunForm($panel);

    $myca = $listbox->Get();

    $panel->Hide();
    undef $panel;
    Newt::Refresh();
    return $ret;
}

# Cert signing request generation for renewal
sub renewCert
{
    my ($csrfile) = @_;

    my $tempDbDir = "/tmp/nss.".$$;

    # Get a comfirmation
    my $msg = "You are about to issue a certificate renewal";
    my $panel = Newt::Panel(1, 2, "Certificate Renewal");
    $panel->Add(0, 0, 
            Newt::TextboxReflowed(60, 10, 10, 0, 
            "Would you like to send a Certificate Request" .
            "for\n\n$servername".
            "\nto a Certificate Authority (CA)?"));

    $panel->Add(0, 1, DoubleButton("Yes", "No"));
    $ret = &RunForm($panel);
    $panel->Hide();
    undef $panel;

    return "Cancel" if $ret eq "Cancel";
   
    # Cert to renew could be in the nss database or in a pem file

    if ($nss) {
        # Renew cert in the nss database
        renewCertNSS($csrfile, $modNssDbDir, $nssDBPrefix, 
                     $nssNickname, $days, $tmpPasswordFile);
    } else {
        # Renew cert in a PEM file
        renewCertOpenSSL($csrfile, $certfile, $keyfile, $cacert, $days);
    }
}

sub genReqWindow
{
    return "Skip" unless $useca;

    $keyfile = $ssltop."/private/".$servername.".key";
    $certfile = $ssltop."/certs/".$servername.".crt";
    
    $num = 0;
    while (-f $ssltop."/certs/".$servername.".$num.csr") {
	$num++;
    }
    $csrfile = $ssltop."/certs/".$servername.".$num.csr";
    
    return renewCert($csrfile) if $renew;
    
    my $msg = "You are about to be asked to enter information that will be ".
	"incorporated into your certificate request to a CA. What you are about to ".
        "enter is what is called a Distinguished Name or a DN.  There are ".
        "quite a few fields but you can leave some blank.";

    my $ret = getCertDetails($servername,$msg, 1);
    return $ret unless ($ret eq "Next");

    if ($nss) {
        genRequestNSS($csrfile, $subject, 730, $randfile, $tmpPasswordFile);
    } else {
        genRequestOpenSSL($keyfile, $csrfile,
                          $subject, 730, $randfile, $tmpPasswordFile);
    }
    
# Now make a temporary cert

    if (!$genreq_mode) {
	    if (!-f $certfile) {
            if ($nss) {
                makeCertNSS($certfile,
                            $subject, $cert_days, $nssNickname,
                            $randfile, $tmpPasswordFile); 
            } else {
                makeCertOpenSSL($keyfile,$certfile,
                                $subject, $cert_days,
                                $randfile, $tmpPasswordFile);
            }
        }
    }
    
    undef $csrtext;
    open(CSR,"<$csrfile");
    while(<CSR>) {
	$csrtext .= $_;
    }
    close(CSR);

    # Fixme: Disabling csr display, not recognized as PEM base 64 encoded
    $csrtext = "" if $renew && !$nss;

    Newt::Suspend();
    
    # Clear the screen
    system("clear");

    if ($myca eq "VeriSign") {
	
	print <<EOT;
You now need to connect to the VeriSign site and submit your CSR. The
page at https://digitalid.verisign.com/server/help/hlpEnrollServer.htm
explains how to do this, and what additional documention will be
required before VeriSign can sign your certificate.

Your CSR is given below. To submit it to VeriSign, go through the
enrollment process starting at
https://digitalid.verisign.com/server/enrollIntro.htm. Paste the CSR,
including the BEGIN and END lines, when prompted in step 4.

$csrtext
EOT
}

    if ($myca eq "Thawte") {
	print <<EOT;
You now need to connect to the Thawte site and submit your CSR. The
page at https://www.thawte.com/certs/server/request.html explains how
to do this, and what additional documention will be required before
Thawte can sign your certificate.

Your CSR is given below. To submit it to Thawte, go to
https://www.thawte.com/cgi/server/step1.exe and select "Web Server
Certificate". Paste the CSR, including the BEGIN and END lines, when
prompted.

$csrtext
EOT
}

    if ($myca eq "Equifax") {
	print <<EOT;
You now need to connect to the Equifax site and submit your CSR. The
page at http://www.equifaxsecure.com/ebusinessid/c2net/ explains how
to do this, and what additional documention will be required before
Equifax can sign your certificate.

Your CSR is given below. To submit it to Equifax, go to
http://www.equifaxsecure.com/ebusinessid/c2net/
Paste the CSR, including the BEGIN and END lines, when prompted.

$csrtext
EOT
}

    if ($myca eq "Other") {
	print <<EOT;
You now need to submit your CSR and documentation to your certificate
authority. Submitting your CSR may involve pasting it into an online
web form, or mailing it to a specific address. In either case, you
should include the BEGIN and END lines.

$csrtext
EOT
}

    print <<EOT;
    
A copy of this CSR has been saved in the file
$csrfile

Press return when ready to continue
EOT
    $_=<STDIN>;
    Newt::Resume();
    return "Next";
}


sub genCertWindow
{
    return "Skip" if $useca;

    $keyfile = $ssltop."/private/".$servername.".key";
    $certfile = $ssltop."/certs/".$servername.".crt";
    
    my $msg = "You are about to be asked to enter information that will be ".
	"made into a self-signed certificate for your server. What you are ".
	"about to ".
	"enter is what is called a Distinguished Name or a DN.  There are ".
	"quite a few fields but you can leave some blank";

    my $ret = getCertDetails($servername,$msg, 0);
    return $ret unless ($ret eq "Next");

    if ($nss) {
        makeCertNSS($certfile, # output
            $subject,$cert_days,$nssNickname,
            $randfile,$tmpPasswordFile);
    } else {
        makeCertOpenSSL($keyfile,$certfile, # output
            $subject,$cert_days,
            $randfile,$tmpPasswordFile);
    }

    return "Next";
}

sub genCACertWindow
{
    return "Skip" if $useca;

    $keyfile = $cadir."/private/".$servername;
    $certfile = $cadir."/".$servername;
    
    my $msg = "You are about to be asked to enter information that will be ".
	"made into a certificate for your CA key. What you are ".
	"about to ".
	"enter is what is called a Distinguished Name or a DN.  There are ".
	"quite a few fields but you can leave some blank";

    my $ret = getCertDetails("",$msg, 0);
    return $ret unless ($ret eq "Next");

    if ($nss) {
        makeCertNSS('',$subject,730,$nssNickname,
                    $randfile,$tmpPasswordFile);
    } else {
        makeCertOpenSSL($keyfile,$certfile,$subject,730,
                        $randfile,$tmpPasswordFile);
    }

    return "Next";
}

sub getRandomDataWindow() 
{
    my $randbits = $bits * 2;

# Get some random data from truerand library
#
    if (!$skip_random) {
	FinishRoot();
	InitRoot(0);
	makerand($randbits,$randfile);
	FinishRoot();

# Get some random data from keystrokes
#
      Newt::Suspend();

      system("$bindir/keyrand $randbits $randfile");

      Newt::Resume();
    } else {
# No extra random seed is being provided to nss. Rely
# on nss faster autoseeding process. The nss utilities
# will prompt the user for some keystrokes.
    $randfile = '';
    }
    return "Next";
}
