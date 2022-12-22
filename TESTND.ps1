#Network Detective Scan
$NetStat = Test-Connection smtp.office365.com -Quiet

$Ques = Read-host 'Credential switch? y or n: '
$Serv = Read-Host 'Is this a server? y or n: '
$Logoff = Read-Host 'Logoff after? y or n: '
if($Ques -match 'y')
{

$Ask = Read-Host 'Enter Admin Username: '

}
if ($NetStat -eq $true -and $Serv -eq 'n')
{
$outbase = $env:COMPUTERNAME

$null = mkdir "C:\Network Detective"


$bigdir = "C:\Network Detective Final\" + $outbase

$null = mkdir $bigdir

$outdir= '"C:\Network Detective"'
$workdir = "C:\Network Detective"
$sddc = '""C:\NDDC\NetworkDetectiveSettings.ndp""'

    $ArgumentList = "-file", $sddc, "-workdir", $outdir, "-outbase", $outbase, "-silent"

    Write-Host 'Directories Created...'

  #Security Scan

  Write-Host 'Starting Security Scan...'

    Start-Process -FilePath "C:\NDDC\sddc.exe" -ArgumentList $ArgumentList -WindowStyle Hidden -Wait

     $ArgumentList2 = "-local", "-workdir", $workdir, "-outdir", $outdir, "-outbase", $outbase, "-silent"

  Write-Host 'Security scan finished...'

  $Deletion = $env:USERPROFILE

$FinalDeleteH = $Deletion + '\' + 'Desktop' + '\'

$ItemChild = Get-ChildItem $FinalDeleteH | Where-Object {$PSItem.Name -match '.sdf'} | Remove-Item

$ChildItem = Get-ChildItem $FinalDeleteH | Where-Object {$PSItem.Name -match '.wdf'} | Remove-Item

     #Local Scan

  Write-Host 'Starting Local Scan...'

    Start-Process -FilePath "nddc.exe" -ArgumentList $ArgumentList2 -WindowStyle Hidden -Wait

Write-Host 'Local scan finished...'


    $CDF = $bigdir  + '\' + $outbase + '.cdf'

    $LDF = $bigdir  + '\' + $outbase + '.ldf'

    $SDF = $bigdir + '\' + $outbase + '.sdf'

    $WDF = $bigdir +  '\' + $outbase + '.wdf'

    cd 'C:\Network Detective'

    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.cdf'} | Move-Item -Destination $CDF

    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.ldf'} | Move-Item -Destination $LDF
    
    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.sdf'} | Move-Item -Destination $SDF

    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.wdf'} | Move-Item -Destination $WDF

    $Filecheck = Get-ChildItem $CDF

    if ($Filecheck.name -match '.cdf')
    {

    Write-Host 'Sending Mail...'

    $secpasswd = ConvertTo-SecureString "EMAILPASSWORD" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("EMAIL", $secpasswd)

$RealFile = Get-ChildItem -Path $bigdir

$FinalFile = 'c:\' + $outbase
$MailFile = 'c:\' + $outbase + '.zip'

Compress-Archive -Path $bigdir -DestinationPath $FinalFile

Send-MailMessage -SmtpServer smtp.office365.com -to EMAIL -From EMAIL -Attachments $MailFile -UseSsl -Port 587 -Credential $cred -Subject 'Church Files'

Write-Host 'Mail Sent!'

    }
    else
    {
    $no_cdf_message = 'No .cdf file on computer ' + $outbase

    Send-MailMessage -SmtpServer smtp.office365.com -to EMAIL -From EMAIL -UseSsl -Port 587 -Credential $cred -Subject $no_cdf_message

    Add-Type -AssemblyName PresentationCore,PresentationFramework

    [System.Windows.MessageBox]::Show('No .cdf File Restart exe')

    exit

    }

    
  #Credential Switcher
  if ($Ques -eq 'y')
  {

  Write-Host 'Credentials Changing'

  $com= $env:COMPUTERNAME
$logon = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName $com | Sort-Object -Property LastLogon -Descending | Select-Object -Property * | Where-Object {$_.LastLogon -match "(\d{14})"} | Foreach-Object { New-Object PSObject -Property @{ Caption = $_.Caption; Name=$_.Name;LastLogon=[datetime]::ParseExact($matches[0], "yyyyMMddHHmmss", $null)}}

if($logon[0].Caption -match $Ask)
{

$RegCheck = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name


Foreach ($SID in $RegCheck)
{

$regsetup = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SID


    $item = Get-ItemProperty $regsetup

    if($item -match $logon[1].Caption)
    {

        $LastSID = $SID

    }

}

#domain name
$logon[1].Name
#logon name 
$logon[1].Caption
#logon SID
$LastSID

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonDisplayName -Value $logon[1].Caption

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonSAMUser -Value $logon[1].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUser -Value $logon[1].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUserSID -Value $LastSID

$Userpath = 'c:\' + 'users\' + $env:USERNAME + '\Desktop\'

$start = $Userpath + 'Delete.exe'

Move-Item -Path "C:\NDDC\Delete.exe" -Destination $Userpath

Write-Host 'Registry Changed'





else
{
$RegCheck = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name


Foreach ($SID in $RegCheck)
{

$regsetup = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SID


    $item = Get-ItemProperty $regsetup

    if($item -match $logon[0].Caption)
    {

        $LastSID = $SID

    }

}

#domain name
$logon[0].Name
#logon name 
$logon[0].Caption
#logon SID
$LastSID

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonDisplayName -Value $logon[0].Caption

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonSAMUser -Value $logon[0].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUser -Value $logon[0].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUserSID -Value $LastSID

$Userpath = 'c:\' + 'users\' + $env:USERNAME + '\Desktop\'

$start = $Userpath + 'Delete.exe'

Write-Host 'Registry Changed'
}
}
}

#Start-Process -FilePath $start -WorkingDirectory $Userpath

Get-Process | Where-Object {$PSItem.Name -match 'Aprocess'} | Stop-Process

$Userpath = 'C:\NDDC\ANetDet.exe'

$outbase = $env:COMPUTERNAME

$MailFile = 'c:\' + $outbase + '.zip'

$bigdir = "C:\Network Detective Final\" + $outbase


Remove-Item 'C:\Network Detective' -Force -Recurse

Remove-Item 'C:\Network Detective Final' -Force -Recurse

Remove-Item $bigdir -Force -Recurse

Remove-Item $MailFile -Force -Recurse

Remove-Item 'C:\NDDC' -Force -Recurse
if ($Logoff -eq 'y')
{
Start-Process -FilePath "cmd.exe" -ArgumentList "/c timeout 30  /nobreak & logoff" -WorkingDirectory 'C:\'
}

Start-Process -FilePath "cmd.exe" -ArgumentList '/c timeout 20 /nobreak & rmdir "C:\Network Detective" /s /q & rmdir "C:\NDDC" /s /q' -WorkingDirectory 'C:\'

exit
}

























Elseif($NetStat -eq $false -or $Serv -eq 'y')
{
Write-Host 'Offline Mode'
$outbase = $env:COMPUTERNAME

$null = mkdir "C:\Network Detective"


$bigdir = "C:\Network Detective Final\" + $outbase

$null = mkdir $bigdir

$outdir= '"C:\Network Detective"'
$workdir = "C:\Network Detective"
$sddc = '""C:\NDDC\NetworkDetectiveSettings.ndp""'

$ArgumentList = "-file", $sddc, "-workdir", $outdir, "-outbase", $outbase, "-silent"

    Write-Host 'Directories Created...'

  #Security Scan

  Write-Host 'Starting Security Scan...'

    Start-Process -FilePath "C:\NDDC\sddc.exe" -ArgumentList $ArgumentList -WindowStyle Hidden -Wait

     $ArgumentList2 = "-local", "-workdir", $workdir, "-outdir", $outdir, "-outbase", $outbase, "-silent"

  Write-Host 'Security scan finished...'

  $Deletion = $env:USERPROFILE

$FinalDeleteH = $Deletion + '\' + 'Desktop' + '\'

$ItemChild = Get-ChildItem $FinalDeleteH | Where-Object {$PSItem.Name -match '.sdf'} | Remove-Item

$ChildItem = Get-ChildItem $FinalDeleteH | Where-Object {$PSItem.Name -match '.wdf'} | Remove-Item

     #Local Scan

  Write-Host 'Starting Local Scan...'

    Start-Process -FilePath "nddc.exe" -ArgumentList $ArgumentList2 -WindowStyle Hidden -Wait

Write-Host 'Local scan finished...'


    $CDF = $bigdir  + '\' + $outbase + '.cdf'

    $LDF = $bigdir  + '\' + $outbase + '.ldf'

    $SDF = $bigdir + '\' + $outbase + '.sdf'

    $WDF = $bigdir +  '\' + $outbase + '.wdf'

    cd 'C:\Network Detective'

    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.cdf'} | Move-Item -Destination $CDF

    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.ldf'} | Move-Item -Destination $LDF
    
    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.sdf'} | Move-Item -Destination $SDF

    Get-ChildItem 'C:\Network Detective' | Where-Object {$PSItem.Name -match '.wdf'} | Move-Item -Destination $WDF

    $Filecheck = Get-ChildItem $CDF

    if ($Filecheck.name -match '.cdf')
    {
    $RealFile = Get-ChildItem -Path $bigdir

    $FinalFile = 'c:\' + $outbase
    $MailFile = 'c:\' + $outbase + '.zip'

    Compress-Archive -Path $bigdir -DestinationPath $FinalFile
    
    }
    else
    {

    Add-Type -AssemblyName PresentationCore,PresentationFramework

    [System.Windows.MessageBox]::Show('No .cdf File Restart exe')

    exit

    }

    
  #Credential Switcher
  if ($Ques -eq 'y')
  {

  Write-Host 'Credentials Changing'

  $com= $env:COMPUTERNAME
$logon = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName $com | Sort-Object -Property LastLogon -Descending | Select-Object -Property * | Where-Object {$_.LastLogon -match "(\d{14})"} | Foreach-Object { New-Object PSObject -Property @{ Caption = $_.Caption; Name=$_.Name;LastLogon=[datetime]::ParseExact($matches[0], "yyyyMMddHHmmss", $null)}}

if($logon[0].Caption -match $Ask)
{

$RegCheck = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name


Foreach ($SID in $RegCheck)
{

$regsetup = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SID


    $item = Get-ItemProperty $regsetup

    if($item -match $logon[1].Caption)
    {

        $LastSID = $SID

    }

}

#domain name
$logon[1].Name
#logon name 
$logon[1].Caption
#logon SID
$LastSID

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonDisplayName -Value $logon[1].Caption

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonSAMUser -Value $logon[1].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUser -Value $logon[1].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUserSID -Value $LastSID

$Userpath = 'c:\' + 'users\' + $env:USERNAME + '\Desktop\'

$start = $Userpath + 'Delete.exe'

Move-Item -Path "C:\NDDC\Delete.exe" -Destination $Userpath

Write-Host 'Registry Changed'


}


else
{
$RegCheck = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name


Foreach ($SID in $RegCheck)
{

$regsetup = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SID


    $item = Get-ItemProperty $regsetup

    if($item -match $logon[0].Caption)
    {

        $LastSID = $SID

    }

}

#domain name
$logon[0].Name
#logon name 
$logon[0].Caption
#logon SID
$LastSID

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonDisplayName -Value $logon[0].Caption

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonSAMUser -Value $logon[0].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUser -Value $logon[0].Name

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -Name LastLoggedonUserSID -Value $LastSID

$Userpath = 'c:\' + 'users\' + $env:USERNAME + '\Desktop\'

$start = $Userpath + 'Delete.exe'

Write-Host 'Registry Changed'
}
}

#Start-Process -FilePath $start -WorkingDirectory $Userpath

Get-Process | Where-Object {$PSItem.Name -match 'Aprocess'} | Stop-Process

$Userpath = 'C:\NDDC\ANetDet.exe'

$outbase = $env:COMPUTERNAME

$MailFile = 'c:\' + $outbase + '.zip'

$bigdir = "C:\Network Detective Final\" + $outbase


Remove-Item 'C:\Network Detective' -Force -Recurse

Remove-Item 'C:\Network Detective Final' -Force -Recurse

Remove-Item $bigdir -Force -Recurse

Remove-Item 'C:\NDDC' -Force -Recurse

$RealMessage = '''Computer offline, please move .zip file to usb and delete.'''

$FinalMessage = '/c timeout 20 /nobreak & rmdir "C:\Network Detective" /s /q & rmdir "C:\NDDC" /s /q & PowerShell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show()'

Start-Process -FilePath "cmd.exe" -ArgumentList $FinalMessage -WorkingDirectory 'C:\'


exit


}

                                                              











   


