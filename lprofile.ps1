###############################################################
#
#local profile - should only be used to load global profile
#
#to install custom local profile on this computer:
#
#	New-Item -itemtype file -force $profile
#	Invoke-WebRequest https://edprivate.blob.core.windows.net/data/lprofile.ps1 -OutFile $profile
# Unblock-File $profile
#
###############################################################

#kelly specific stuff
if($env:userdnsdomain -match "kellyservices") {
  $AtKelly=$TRUE
	#in case H drive doesn't exist (kelly) due to elevated privs. add it back...
	if(!(Get-PSDrive -Name H -ErrorAction SilentlyContinue)) {
	  "... Mapping H drive ..."
	  New-PSDrive -name H -PSProvider FileSystem -root "\\hqw2fs01\quilleo$" -ErrorAction SilentlyContinue > $null
	}
}

#try to find global profile

$tmpdir="$env:USERPROFILE\tmp"
mkdir $tmpdir -ErrorAction SilentlyContinue
$ProgressPreference = "silentlyContinue"  #stop the annoying progress bar from invoke-web...
Invoke-WebRequest https://edprivate.blob.core.windows.net/data/gprofile.ps1 -OutFile $tmpdir/gprofile.ps1
if($?) {
  write-host "... Downloaded gprofile from azure ..."
  if($AtKelly) {
    cp $tmpdir/gprofile.ps1 "\\hqw2fs01\quilleo$\gprofile.ps1"
  }
  cp $tmpdir/gprofile.ps1 $env:userprofile
}else {
  write-host "... NOT able to download gprofile from azure ..."
}
$ProgressPreference = "Continue"  #reset back to default

#h: drive for kelly
$gfilelist="$env:userprofile\gprofile.ps1","\\hqw2fs01\quilleo$\gprofile.ps1","i:\my drive\global\gprofile.ps1"
foreach($gfile in $gfilelist) {
  if ( test-path $gfile ) {
    $gprofile=$TRUE
    $gsource=$gfile
    $gcontents=get-content -path $gfile | out-string
    break
  }
}

#if we couldn't find it on web try start dir as a last chance
if($gprofile) {
#exec the gprofile code
  write-host "... Loading code from: $gsource ..."
  #$gcontents | gm
  Invoke-Expression -Command $gcontents
}else {
#didn't find the global profile so lets load in some essential stuff
#
##aliases
#
#
  new-alias grep findstr
#grep as select-string doesn't process object lists as you would think: gal | select-string grep to see what i am saing
#new-alias grep Select-String
#alternate grep method
#function grep {
#  $input | out-string -stream | select-string $args
#}
  new-alias less more
  new-alias df get-psdrive
  new-alias vim 'C:\Program Files (x86)\Vim\vim74\vim.exe'
  new-alias vi vim
  new-alias gvim 'C:\Program Files (x86)\Vim\vim74\gvim.exe'
  new-alias lsltr ls-ltr
  function ls-ltr {gci | sort LastWriteTime}
  function head {$input | select-object -first 10}
}
#### endif global profile not found
#

