function New-SlackPost {
    param ($issue)
    
    $payload = @{
        "channel" = "#psmonitor";
        "text" = "$issue";
        "icon_emoji" = ":bomb:";
        "username" = "PSMonitor";
    }

    Write-Verbose "Sending Slack Message"
    
    $slackWebRequest = @{
        Uri = "https://hooks.slack.com/services/$SlackToken"
        Method = "POST"
        Body = (ConvertTo-Json -Compress -InputObject $payload)
    }

    Invoke-WebRequest @slackWebRequest    

}
function Send-AlertCleared {
    Param($InError)
    Write-Verbose "Sending Email"
    Write-Verbose "Output is --  $InError"
    
    #Mail Server Config
    $NBN = (Get-ADDomain).NetBIOSName
    $Domain = (Get-ADDomain).DNSRoot
    $smtpServer = $Configuration.SMTPServer
    $smtp = new-object Net.Mail.SmtpClient($smtpServer)
    $msg = new-object Net.Mail.MailMessage

    #Send to list:    
    $emailCount = ($Configuration.MailTo).Count
    If ($emailCount -gt 0){
        $Emails = $Configuration.MailTo
        foreach ($target in $Emails){
        Write-Verbose "email will be sent to $target"
        $msg.To.Add("$target")
        }
    }
    Else{
        Write-Verbose "No email addresses defined"
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17030 -EntryType Error -message "ALERT - No email addresses defined.  Alert email can't be sent!" -category "17030"
    }
    #Message:
    $msg.From = $Configuration.MailFrom
    $msg.ReplyTo = $Configuration.MailFrom
    $msg.subject = "$NBN AD Internal Time Sync - Alert Cleared!"
    $msg.body = @"
        The previous Internal AD Time Sync alert has now cleared.

        Thanks.
"@
    #Send it
    $smtp.Send($msg)
}
function Send-Mail {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [String]
        $emailOutput
    )
    
    Write-Verbose "Sending Email"
    Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17034 -EntryType Information -message "ALERT Email Sent" -category "17034"
    Write-Verbose "Output is --  $emailOutput"
    
    #Mail Server Config
    $NBN = (Get-ADDomain).NetBIOSName
    $Domain = (Get-ADDomain).DNSRoot
  

    #Send to list:    
    $emailCount = ($Configuration.MailTo).Count

    If ($emailCount -gt 0){
        $Emails = $Configuration.MailTo
        foreach ($target in $Emails){
        Write-Verbose "email will be sent to $target"
        $msg.To.Add("$target")
        }
    }
    
    Else{
        Write-Verbose "No email addresses defined"
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17030 -EntryType Error -message "ALERT - No email addresses defined.  Alert email can't be sent!" -category "17030"
    }
    
    #Message:
    $mail = @{

        To = $Configuration.MailTo
        From = $Configuration.MailFrom
        ReplyTo = $Configuration.MailFrom
        SMTPServer = $Configuration.SMTPServer
        Subject = "$NBN AD Internal Time Sync Alert!"
        Body = @"
        Time of Event: $((get-date))`r`n $emailOutput
        See the following support article $SupportArticle
"@
        BodyAsHtml = $true

    }

    Send-MailMessage @mail
   
}

function Copy-Files ($scriptToDeploy)
{
    $targets = Get-Content "C:\Scripts\RemotePSMonitorServers.txt"
    
    foreach ($Server in $Targets)
    {
        Write-output "Copying to $Server..."
        Copy-Item  $scriptToDeploy -Destination "\\$Server\Scripts\"
    }
    
}


<# Comment out to test module loading.
$scriptToDeploy = "C:\Scripts\Test-ADReplication.ps1"
Copy-Files $scriptToDeploy

$scriptToDeploy = "C:\Scripts\ADConfig.json"
Copy-Files $scriptToDeploy

$scriptToDeploy = "C:\Scripts\Test-ADLastBackupDate.ps1"
Copy-Files $scriptToDeploy

$scriptToDeploy = "C:\Scripts\Test-ADObjectReplication.ps1"
Copy-Files $scriptToDeploy

$scriptToDeploy = "C:\Scripts\Test-ADTimeSync.ps1"
Copy-Files $scriptToDeploy

$scriptToDeploy = "C:\Scripts\Test-ADTimeSyncToExternalNTP.ps1"
Copy-Files $scriptToDeploy

$scriptToDeploy = "C:\Scripts\Test-SYSVOL-Replication.ps1"
Copy-Files $scriptToDeploy

#>
function Get-ADConfig {
    <#
        .SYNOPSIS
        Converts json config data into usable powershell object

        .PARAMETER Configuration

        Location of the json file which hold module configuration data
        .EXAMPLE

        Get-ADConfig "C:\configs\ADConfig.json"


    #>
    [cmdletBinding()]
    [Alias('Get-ADHealthConfig')]
    Param(
        [Parameter(Position=0)]
        [ValidateScript({ Test-Path $_})]
        [String]
        $ConfigurationFile = "$PSScriptRoot\Config\ADConfig.json"
    )

    begin {}

    process {

        $Global:Configuration = Get-Content $ConfigurationFile | ConvertFrom-JSON

        $Configuration
    }

    end {}

}
function Get-ADLastBackupDate {
    [CmdletBinding()]
    Param()
    <#
    .SYNOPSIS
    Check AD Last Backup Date
    
    .DESCRIPTION
    This script Checks AD for the last backup date

    .EXAMPLE
    Run as a scheduled task.  Use Event Log consolidation tools to pull and alert on issues found.

    .EXAMPLE
    Run in verbose mode if you want on-screen feedback for testing
   
    .NOTES
    Authors: Mike Kanakos, Greg Onstot
    Version: 0.6.3
    Version Date: 04/19/2019
    
    Event Source 'PSMonitor' will be created

    EventID Definition:
    17050 - Failure
    17051 - Beginning of test
    17052 - Successful Test Result
    17053 - End of test
    17054 - Alert Email Sent
    #>

    Begin {
        Import-Module activedirectory

        $null = Get-ADConfig

        $SupportArticle = $Configuration.SupportArticle

        if (![System.Diagnostics.EventLog]::SourceExists("PSMonitor")) {
            write-verbose "Adding Event Source."
            New-EventLog -LogName Application -Source "PSMonitor"
        }#end if

        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17051 -EntryType Information -message "START of AD Backup Check ." -category "17051"
        
        $Domain = (Get-ADDomain).DNSRoot
        $Regex = '\d\d\d\d-\d\d-\d\d'
        $CurrentDate = Get-Date
        $MaxDaysSinceBackup = $Configuration.MaxDaysSinceBackup
        
    }#End Begin

    Process {
        #get the date of last backup from repadmin command using regex
        $LastBackup = (repadmin /showbackup $Domain | Select-String $Regex |ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } )[0]
        #Compare the last backup date to today's date
        $Result = (New-TimeSpan -Start $LastBackup -End $CurrentDate).Days
        
        Write-Verbose "Last Active Directory backup occurred on $LastBackup! $Result days is less than the alert criteria of $MaxDaysSinceBackup day."
                        
        #Test if result is greater than max allowed days without backup
        If ($Result -gt $MaxDaysSinceBackup) {
            
            Write-Verbose "Last Active Directory backup occurred on $LastBackup! $Result days is higher than the alert criteria of $MaxDaysSinceBackup day."
            
            $emailOutput = "Last Active Directory backup occurred on $LastBackup! $Result days is higher than the alert criteria of $MaxDaysSinceBackup day."
            
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17050 -EntryType Warning -message "ALERT - AD Backup is not current.  $emailOutput" -category "17050"
            
            $global:CurrentFailure = $true

            $mailParams = @{
                To = $Configuration.MailTo
                From = $Configuration.MailFrom
                SmtpServer = $Configuration.SmtpServer
                Subject = "AD Backup Check Alert! Backup is $Result days old"
                Body = $emailOutput
                BodyAsHtml = $true
          }

          Send-MailMessage @mailParams
          #Write-Verbose "Sending Slack Alert"
          #New-SlackPost "Alert - AD Last Backup is $Result days old"
        }else {
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17052 -EntryType Information -message "SUCCESS - Last Active Directory backup occurred on $LastBackup! $Result days is less than the alert criteria of $MaxDaysSinceBackup day." -category "17052"
        }#end else
        
    
    }#End Process
    
    End {
        
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17053 -EntryType Information -message "END of AD Backup Check ." -category "17053"
        
        If (!$CurrentFailure){
            Write-Verbose "No Issues found in this run"
            $InError = Get-EventLog application -After (Get-Date).AddHours(-24) | where {($_.InstanceID -Match "17050")} 
            
            If ($InError) {
                Write-Verbose "Previous Errors Seen"
                #Previous run had an alert
                #No errors foun during this test so send email that the previous error(s) have cleared
                $alertclearedParams = @{
                    To = $Configuration.MailTo
                    From = $Configuration.MailFrom
                    SmtpServer = $Configuration.SmtpServer
                    Subject = "AD Internal Time Sync - Alert Cleared!"
                    Body = "The previous Internal AD Time Sync alert has now cleared."
                    BodyAsHtml = $true
              }
    
              Send-MailMessage @alertclearedParams
              #Write-Verbose "Sending Slack Message - AD Backup Alert Cleared"
              #New-SlackPost "The previous alert, for AD Last Backup has cleared."
                #Write-Output $InError
            }#End if
        
        }#End if

    }#End End

}#End Function
Function Get-DCDiskspace {
      [cmdletBinding()]
      Param(
            [Parameter(Mandatory,Position=0)]
            [String]
            $DriveLetter
      )
      
      begin {
            Import-Module ActiveDirectory
            #Creates a global $configuration variable
            $null = Get-ADConfig
      }

      process {
            $DClist = (get-adgroupmember "Domain Controllers").name
            $FreeDiskThreshold = $Configuration.FreeDiskThreshold

            ForEach ($server in $DClist){

                  $disk = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $server | Where-Object { $_.DeviceId -eq $DriveLetter}
                  $Size = (($disk | Measure-Object -Property Size -Sum).sum/1gb)
                  $FreeSpace = (($disk | Measure-Object -Property FreeSpace -Sum).sum/1gb)
                  $freepercent = [math]::round(($FreeSpace / $size) * 100,0)
                  $Diskinfo = [PSCustomObject]@{
                        Drive = $disk.Name
                        "Total Disk Size (GB)" = [math]::round($size,2)
                        "Free Disk Size (GB)" = [math]::round($FreeSpace,2)
                        "Percent Free (%)" = $freepercent
                  } #End $DiskInfo Calculations
            
            If ($Diskinfo.'Percent Free (%)' -lt $FreeDiskThreshold){
                  $Subject = "Low Disk Space: Server $Server"
                  $EmailBody = @"
            
            
            Server named <font color="Red"><b> $Server </b></font> is running low on disk space on drive C:!
            <br/>
            $($Diskinfo | ConvertTo-Html -Fragment)
            <br/>
            Time of Event: <font color="Red"><b>"""$((get-date))"""</b></font><br/>
            <br/>
            THIS EMAIL WAS AUTO-GENERATED. PLEASE DO NOT REPLY TO THIS EMAIL.
"@

                  $mailParams = @{
                        To = $Configuration.MailTo
                        From = $Configuration.MailFrom
                        SmtpServer = $Configuration.SmtpServer
                        Subject = $Subject
                        Body = $EmailBody
                        BodyAsHtml = $true
                  }
                  Send-MailMessage @mailParams
            
            } #End If


            } # End ForEach

      }

      end {}

}

function Set-PSADHealthConfig
{
    <#
        .SYNOPSIS
        Sets the configuration data for this module

        .PARAMETER PSADHealthConfigPath

        The filesystem location to store configuration file data.

        .PARAMETER SMTPServer

        The smtp server this module will use for reports.

        .EXAMPLE
        Set-PSADHealthConfig -SMTPServer email.company.com

        .EXAMPLE
        Set-PSADHealthConfig -MailFrom admonitor@foobar.come -MailTo directoryadmins@foobar.com

        .EXAMPLE
        Set-PSADHealthConfig -MaxDaysSinceBackup 12


    #>

    [cmdletBinding()]
    Param(

        [Parameter(Position=0)]
        $PSADHealthConfigPath = "$($PSScriptRoot)\Config\ADConfig.json",

        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]
        $SMTPServer = "mail.server.fqdn",

        [Parameter()]
        [String]
        $MailFrom,

        [Parameter()]
        [String[]]
        $MailTo,

        [Parameter()]
        [String]
        $MaxDaysSinceBackup,

        [Parameter()]
        [Int]
        $MaxIntTimeDrift,

        [Parameter()]
        [Int]
        $MaxExtTimeDrift,

        [Parameter()]
        [string]
        $ExternalTimeServer,

        [Parameter()]
        [Int]
        $MaxObjectReplCycles,

        [Parameter()]
        [Int]
        $MaxSysvolReplCycles,

        [Parameter()]
        [String]
        $SupportArticleUrl,

        [Parameter()]
        [String]
        $SlackToken
    )

    
    $config = Get-ADConfig -ConfigurationFile $PSADHealthConfigPath
    
    Switch($PSBoundParameters.Keys){
        'SMTPServer' {
            $config.smtpserver = $SMTPServer
         }
        'MailFrom' {
            $config.MailFrom = $MailFrom
        }
        'MailTo' {
            $config.MailTo = $MailTo
        }
        'MaxDaysSinceBackup' {
            $config.MaxDaysSinceBackup = $MaxDaysSinceBackup
        }
        'MaxIntTimeDrift' {
            $config.MaxIntTimeDrift = $MaxIntTimeDrift
        }
        'MaxExtTimeDrift' {
            $config.MaxExtTimeDrift = $MaxExtTimeDrift
        }
        'ExternalTimeServer' {
            $config.ExternalTimeSvr = $ExternalTimeServer
        }
        'MaxObjectReplCycles' {
            $config.MaxObjectReplCycles = $MaxObjectReplCycles
        }
        'MaxSysvolReplCycles' {
            $config.MaxSysvolReplCycles = $MaxSysvolReplCycles
        }
        'SupportArticleUrl' {
            $config.SupportArticle = $SupportArticleUrl
        }
        'SlackToken' {
            $config.SlackToken = $SlackToken
        }

    }
    
    $config | ConvertTo-Json | Set-Content $PSADHealthConfigPath
	
}
function Test-ADConfigMailer {


    begin { $null = Get-ADConfig }


    process {

        $mailParams = @{
            To = $Configuration.MailTo
            From = $Configuration.MailFrom
            SmtpServer = $Configuration.SmtpServer
            Subject = "Testing PSADHealth Mail Capability"
            Body = "If you can read this, your scripts can alert via email!"
            BodyAsHtml = $true
        }

        Send-MailMessage @mailParams
    }
    
}
function Test-ADObjectReplication {
    [CmdletBinding()]
    Param()
    <#
    .SYNOPSIS
    Monitor AD Object Replication
    
    .DESCRIPTION
    Each run of the script creates a unique test object in the domain, and tracks it's replication to all other DCs in the domain.
    By default it will query the DCs for about 60 minutes.  If after 60 loops the object hasn't repliated the test will terminate and create an alert.

    .EXAMPLE
    Run as a scheduled task.  Use Event Log consolidation tools to pull and alert on issues found.

    .EXAMPLE
    Run in verbose mode if you want on-screen feedback for testing
   
    .NOTES
    Author Greg Onstot
    Version: 0.6.3
    Version Date: 04/18/2019

    This script must be run from a Win10, or Server 2016 system.  It can target older OS Versions.

    Event Source 'PSMonitor' will be created

    EventID Definition:
    17010 - Failure
    17011 - Cycle Count
    17012 - Test Object not yet on DC
    17013 - Test Object on DC
    17014 - Tests didn't complete in alloted time span
    17015 - Job output
    17016 - Test Object Created
    17017 - Test Object Deleted
    17018 - 1 minute Sleep
    17019 - Posible old object detected
    #>

    Begin {
        Import-Module activedirectory
        $NBN = (Get-ADDomain).NetBIOSName
        $Domain = (Get-ADDomain).DNSRoot
        $domainname = (Get-ADDomain).dnsroot
        $null = Get-ADConfig
        $SupportArticle = $Configuration.SupportArticle
        if (![System.Diagnostics.EventLog]::SourceExists("PSMonitor")) {
            write-verbose "Adding Event Source."
            New-EventLog -LogName Application -Source "PSMonitor"
        }
        $continue = $true
        $CurrentFailure = $false
        $existingObj = $null
        $DCs = (Get-ADDomainController -Filter *).Name 
        $SourceSystem = (Get-ADDomain).pdcemulator
        [int]$MaxCycles = $Configuration.MaxObjectReplCycles
    }

    Process {
        if (Test-NetConnection $SourceSystem -Port 445 -InformationLevel Quiet) {
            Write-Verbose 'PDCE is online'
            $tempObjectPath = (Get-ADDomain).computersContainer
            $existingObj = Get-ADComputer -filter 'name -like "ADRT-*"' -prop * -SearchBase "$tempObjectPath" |Select-Object -ExpandProperty Name
            If ($existingObj){
                Write-Verbose "Warning - Cleanup of a old object(s) may not have occured.  Object(s) starting with 'ADRT-' exists in $tempObjectPath : $existingObj  - Please review, and cleanup if required."
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17019 -EntryType Warning -message "WARNING - AD Object Replication Cleanup of old object(s) may not have occured.  Object(s) starting with 'ADRT-' exists in $tempObjectPath : $existingObj.  Please review, and cleanup if required." -category "17019"
                #Write-Verbose "Sending Slack Alert"
                #New-SlackPost "Alert - Cleanup of a old object(s) may not have occured.  Object(s) starting with 'ADRT-' exists in $tempObjectPath : $existingObj  - Please review, and cleanup if required."
            }

            $site = (Get-ADDomainController $SourceSystem).site
            $startDateTime = Get-Date
            [string]$tempObjectName = "ADRT-" + (Get-Date -f yyyyMMddHHmmss)
            
            New-ADComputer -Name "$tempObjectName" -samAccountName "$tempObjectName" -Path "$tempObjectPath" -Server $SourceSystem -Enabled $False
            
            Write-Verbose "Object created for tracking - $tempObjectName in $site"
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17016 -EntryType Information -message "CREATED AD Object Replication Test object - $tempObjectName  - has been created on $SourceSystem in site - $site" -category "17016"
            $i = 0
        }
        else {
            Write-Verbose 'PDCE is offline.  You should really resolve that before continuing.'
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17010 -EntryType Error -message "FAILURE AD Object Replication - Failed to connect to PDCE - $SourceSystem  in site - $site" -category "17010"
            $Alert = "In $domainname Failed to connect to PDCE - $dc in site - $site.  Test stopping!  See the following support article $SupportArticle"
            $CurrentFailure = $true
            Send-Mail $Alert
            #Write-Verbose "Sending Slack Alert"
            #New-SlackPost "Alert - PDCE is Offline in $domainname, AD Object Replication test has exited."
            Exit
        }

        While ($continue) {
            $i++
            Write-Verbose 'Sleeping for 1 minute.'
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17018 -EntryType Information -message "SLEEPING AD Object Replication  for 1 minute" -category "17018"
            Start-Sleep 60
            $replicated = $true
            Write-Verbose "Cycle - $i"
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17011 -EntryType Information -message "CHECKING AD Object Replication ADRepl Cycle $i" -category "17011"
        
            Foreach ($dc in $DCs) {
                $site = (Get-ADDomainController $dc).site
                if (Test-NetConnection $dc -Port 445 -InformationLevel Quiet) {
                    Write-Verbose "Online - $dc"
                    $connectionResult = "SUCCESS"
                }
                else {
                    Write-Verbose "!!!!!OFFLINE - $dc !!!!!"
                    $connectionResult = "FAILURE"
                    Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17010 -EntryType Error -message "FAILURE AD Object Replication failed to connect to DC - $dc in site - $site" -category "17010"
                    
                    $CurrentFailure = $true
                    if ($i -eq 10){
                        $Alert = "In $domainname Failed to connect to DC - $dc in site - $site.  See the following support article $SupportArticle"
                        #If we get a failure on the 10th run, send an email for additional visibility, but not spam on every pass if a server or site is offline.
                        Send-Mail $Alert
                        #Write-Verbose "Sending Slack Alert"
                        #New-SlackPost "Alert - In $domainname Failed to connect to DC - $dc in site - $site."
                    }
                    
                }

                # If The Connection To The DC Is Successful
                If ($connectionResult -eq "SUCCESS") {
                    Try {	
                        $Milliseconds = (Measure-Command {$Query = Get-ADComputer $tempObjectName -Server $dc | select Name}).TotalMilliseconds
                        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17013 -EntryType information -message "SUCCESS AD Object Replication Test object replicated to - $dc in site - $site - in $Milliseconds ms. " -category "17013"
                        write-Verbose "SUCCESS! - Replicated -  $($query.Name) - $($dc) - $site - $Milliseconds"
                    }
                    Catch {
                        write-Verbose "PENDING! - Test object $tempObjectName does not exist on $dc in $site."
                        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17012 -EntryType information -message "PENDING AD Object Replication Test object pending replication to - $dc in site - $site. " -category "17012"
                        $replicated = $false
                    }    
                }
        		
                # If The Connection To The DC Is Unsuccessful
                If ($connectionResult -eq "FAILURE") {
                    Write-Verbose "     - Unable To Connect To DC/GC And Check For The Temp Object..."
                    Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17010 -EntryType Error -message "FAILURE AD Object Replication failed to connect to DC - $dc in site - $site" -category "17010"
                    $Alert = "In $domainname Failed to connect to DC - $dc in site - $site.   See the following support article $SupportArticle"
                    $CurrentFailure = $true
                    Send-Mail $Alert
                }
            }

            If ($replicated) {
                $continue = $false
            } 

            If ($i -gt $MaxCycles) {
                $continue = $false
                #gather event history to see which DC did, and which did not, get the replication
                $list = Get-EventLog application -After (Get-Date).AddHours(-2) | where {($_.InstanceID -Match "17012") -OR ($_.InstanceID -Match "17013") -OR ($_.InstanceID -Match "17016")} 
                $RelevantEvents = $list |Select InstanceID,Message |Out-String
                Write-Verbose "Cycle has run $i times, and replication hasn't finished.  Need to generate an alert."
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17014 -EntryType Warning -message "INCOMPLETE AD Object Replication Test cycle has run $i times without the object succesfully replicating to all DCs" -category "17014"
                
                $Alert = "In $domainname - the AD Object Replication Test cycle has run $i times without the object succesfully replicating to all DCs.  
                Please see the following support article $SupportArticle to help investigate
                
                Recent history:
                $RelevantEvents
                "
                $CurrentFailure = $true
                Send-Mail $Alert
                #Write-Verbose "Sending Slack Alert"
                #$New-SlackPost "Alert - In $domainname - the AD Object Replication Test cycle has run $i times without the object succesfully replicating to all DCs."                        
            } 
        }
    }

    End {
        # Show The Start Time, The End Time And The Duration Of The Replication
        $endDateTime = Get-Date
        $duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
        $output = "`n  Start Time......: $(Get-Date $startDateTime -format "yyyy-MM-dd HH:mm:ss")"
        $output = $output + "`n  End Time........: $(Get-Date $endDateTime -format "yyyy-MM-dd HH:mm:ss")"
        $output = $output + "`n  Duration........: $duration Seconds"
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17015 -EntryType Information -message "Test cycle has Ended - $output" -category "17015"
        
        Write-Verbose "`n  Start Time......: $(Get-Date $startDateTime -format "yyyy-MM-dd HH:mm:ss")"
        Write-Verbose "  End Time........: $(Get-Date $endDateTime -format "yyyy-MM-dd HH:mm:ss")"
        Write-Verbose "  Duration........: $duration Seconds"
        
        # Delete The Temp Object On The RWDC
        Write-Verbose "  Deleting AD Object File..."
        Remove-ADComputer $tempObjectName -Confirm:$False
        Write-Verbose "  AD Object [$tempObjectName] Has Been Deleted."
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17017 -EntryType Information -message "DELETED AD Object Replication test object - $tempObjectName  - has been deleted." -category "17017"

        If (!$CurrentFailure){
            Write-Verbose "No Issues found in this run"
            $InError = Get-EventLog application -After (Get-Date).AddHours(-2) | where {($_.InstanceID -Match "17010") -or ($_.InstanceID -Match "17014")} 
            If ($InError) {
                Write-Verbose "Previous Errors Seen"
                #Previous run had an alert
                #No errors foun during this test so send email that the previous error(s) have cleared
                Send-AlertCleared
                #Write-Verbose "Sending Slack Message - Alert Cleared"
                #New-SlackPost "The previous alert, for AD Object Replication, has cleared."
                #Write-Output $InError
            }#End if
        }#End if

    }
}
function Test-ADReplication {
    [CmdletBinding()]
    Param()
    <#
    .SYNOPSIS
    Monitor AD Object Replication
    
    .DESCRIPTION
    This script monitors DCs for Replication Failures

    .EXAMPLE
    Run as a scheduled task.  Use Event Log consolidation tools to pull and alert on issues found.

    .EXAMPLE
    Run in verbose mode if you want on-screen feedback for testing
   
    .NOTES
    Authors: Mike Kanakos, Greg Onstot
    Version: 0.6.2
    Version Date: 04/18/2019

    Event Source 'PSMonitor' will be created

    EventID Definition:
    17020 - Failure
    17021 - Beginning of test
    17022 - Testing individual systems
    17023 - End of test
    17024 - Alert Email Sent
    #>

    Begin {
        Import-Module activedirectory
        $null = Get-ADConfig
        $SupportArticle = $Configuration.SupportArticle
        if (![System.Diagnostics.EventLog]::SourceExists("PSMonitor")) {
            write-verbose "Adding Event Source."
            New-EventLog -LogName Application -Source "PSMonitor"
        }
        #$DClist = (Get-ADGroupMember -Identity 'Domain Controllers').name  #For RWDCs only, RODCs are not in this group.
        $DClist = (Get-ADDomainController -Filter *).name  # For ALL DCs
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17021 -EntryType Information -message "START AD Replication Test Cycle ." -category "17021"
    }#End Begin

    Process {
        Foreach ($server in $DClist) {
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17022 -EntryType Information -message "CHECKING AD Replication - Server - $server" -category "17022"
            Write-Verbose "TESTING - $server"
            $OutputDetails = $null
            $Result = (Get-ADReplicationFailure -Target $server).failurecount
            Write-Verbose "$server - $Result"
            $Details = Get-ADReplicationFailure -Target $server
            $errcount = $Details.FailureCount
            $name = $Details.server
            $Fail = $Details.FirstFailureTime
            $Partner = $Details.Partner
        
            If ($result -ne $null -and $Result -gt 1) {
                $OutputDetails = "ServerName: `r`n  $name `r`n FailureCount: $errcount  `r`n `r`n    FirstFailureTime: `r`n $Fail  `r`n `r`n Error with Partner: `r`n $Partner  `r`n `r`n -  See the following support article $SupportArticle"
                Write-Verbose "Failure - $OutputDetails"
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17020 -EntryType Warning -message "FAILURE AD Replicaion on $server  -  $OutputDetails ." -category "17020"
                $global:CurrentFailure = $true
                Send-Mail $OutputDetails
                #Write-Verbose "Sending Slack Alert"
                #New-SlackPost "Alert - FAILURE AD Replicaion on $server  -  $OutputDetails ."
            } #End if
        }#End Foreach
    }#End Process

    
    End {
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17023 -EntryType Information -message "END of AD Replication Test Cycle ." -category "17023"
        If (!$CurrentFailure){
            Write-Verbose "No Issues found in this run"
            $InError = Get-EventLog application -After (Get-Date).AddHours(-1) | where {($_.InstanceID -Match "17020")} 
            If ($InError.Count -gt 1) {
                Write-Verbose "Previous Errors Seen"
                #Previous run had an alert
                #No errors foun during this test so send email that the previous error(s) have cleared
                Send-AlertCleared
                #Write-Verbose "Sending Slack Message - Alert Cleared"
                #New-SlackPost "The previous alert, for AD Replication, has cleared."
                #Write-Output $InError
            }#End if
        }#End if
    }#End End
}#End Function
# Test-ADServices.ps1
function Test-ADServices {
    [cmdletBinding()]
    Param()

    begin {
        Import-Module ActiveDirectory
        #Creates a global $configuration variable
        $null = Get-ADConfig
    }

    process {
        $DClist = (get-adgroupmember "Domain Controllers").name
        $collection = @('ADWS',
                        'DHCPServer',
                        'DNS',
                        'DFS',
                        'DFSR',
                        'Eventlog',
                        'EventSystem',
                        'KDC',
                        'LanManWorkstation',
                        'LanManServer',
                        'NetLogon',
                        'NTDS',
                        'RPCSS',
                        'SAMSS',
                        'W32Time')

        

        forEach ($server in $DClist){
            
            forEach ($service in $collection){
                try {
                   $s = Get-Service -Name $Service -Computername $server -ErrorAction Stop
                   $s
                }
                
                catch {
                    Out-Null
                }


                if($s.status -eq "Stopped"){


                    $Subject = "Windows Service: $($s.Displayname), is stopped on $server "
                    
                    $EmailBody = @"
                                Service named <font color=Red><b>$($s.Displayname)</b></font> is stopped!
                                Time of Event: <font color=Red><b>"""$((get-date))"""</b></font><br/>
                                <br/>
                                THIS EMAIL WAS AUTO-GENERATED. PLEASE DO NOT REPLY TO THIS EMAIL.
"@
                
                    $mailParams = @{
                        To = $Configuration.MailTo
                        From = $Configuration.MailFrom
                        SmtpServer = $Configuration.SmtpServer
                        Subject = $Subject
                        Body = $EmailBody
                        BodyAsHtml = $true
                    }

                    Send-MailMessage @mailParams
                
                } #End If

            } #Service Foreach
        
        } #DCList Foreach
    
    } #Process

} #function
Function Test-DCsOnline {
    [cmdletBinding()]
    Param()

    Begin {
        Import-Module ActiveDirectory
        #Creates a global $configuration variable
        $null = Get-ADConfig
    }
    
    Process {
        $DClist = (get-adgroupmember "Domain Controllers").name

        ForEach ($server in $DClist){

            if  ((!(Test-Connection -ComputerName $Server -quiet -count 4)))
            {
                $Subject = "Server $Server is offline"
                $EmailBody = @"
        
        
        Server named <font color="Red"><b> $Server </b></font> is offline!
        Time of Event: <font color="Red"><b> $((get-date))</b></font><br/>
        <br/>
        THIS EMAIL WAS AUTO-GENERATED. PLEASE DO NOT REPLY TO THIS EMAIL.
"@

                $mailParams = @{
                    To = $Configuration.MailTo
                    From = $Configuration.MailFrom
                    SmtpServer = $Configuration.SmtpServer
                    Subject = $Subject
                    Body = $EmailBody
                    BodyAsHtml = $true
                }
                Send-MailMessage @mailParams

            } #End if
        }#End Foreach
}
    End {}
}
# Test-ExternalDNSServers.ps1
Function Test-ExternalDNSServers {
    [cmdletBinding()]
    Param()

    begin {
        Import-Module ActiveDirectory
        #Creates a global $configuration variable
        $null = Get-ADConfig
    }

    process {
        $DClist = (get-adgroupmember "Domain Controllers").name
        $ExternalDNSServers = $Configuration.ExternalDNSServers 

        ForEach ($server in $DClist){

            ForEach ($DNSServer in $ExternalDNSServers) {
                
            if  ((!(Invoke-Command -ComputerName $server -ScriptBlock { Test-Connection $args[0] -Quiet -Count 1} -ArgumentList $DNSServer)))
            {
                    
                    $Subject = "External DNS $DNSServer is unreachable"
                    $EmailBody = @"
        
        
                    A Test connection from <font color="Red"><b> $Server </b></font> to $DNSServer was unsuccessful!
                    Time of Event: <font color="Red"><b> """$((get-date))"""</b></font><br/>
                    <br/>
                    THIS EMAIL WAS AUTO-GENERATED. PLEASE DO NOT REPLY TO THIS EMAIL.
"@
         
                    $mailParams = @{
                        To = $Configuration.MailTo
                        From = $Configuration.MailFrom
                        SmtpServer = $Configuration.SmtpServer
                        Subject = $Subject
                        Body = $EmailBody
                        BodyAsHtml = $true
                    }

                    Send-MailMessage @mailParams

                } #End if
            
            }# End Foreach (DCLIst)
        
        } # End ForEach (ExternalDNSServers)

    }

    end {}
}
function Test-ADExternalTimeSync {
    [CmdletBinding()]
    Param()
    <#
    .SYNOPSIS
    Monitor AD External Time Sync
    
    .DESCRIPTION
    This script monitors External NTP to the PDCE for Time Sync Issues

    .EXAMPLE
    Run as a scheduled task.  Use Event Log consolidation tools to pull and alert on issues found.

    .EXAMPLE
    Run in verbose mode if you want on-screen feedback for testing
   
    .NOTES
    Authors: Mike Kanakos, Greg Onstot
    Version: 0.7.2
    Version Date: 4/18/2019
        
    Event Source 'PSMonitor' will be created

    EventID Definition:
    17040 - Failure
    17041 - Beginning of test
    17042 - Testing individual systems
    17043 - End of test
    17044 - Alert Email Sent
    17045 - Automated Repair Attempted
    #>

    Begin {
        Import-Module activedirectory
        $CurrentFailure = $null
        $null = Get-ADConfig
        if (![System.Diagnostics.EventLog]::SourceExists("PSMonitor")) {
            write-verbose "Adding Event Source."
            New-EventLog -LogName Application -Source "PSMonitor"
        }#end if

        #$DClist = (Get-ADGroupMember -Identity 'Domain Controllers').name  #For RWDCs only, RODCs are not in this group.
        $PDCEmulator = (Get-ADDomainController -Discover -Service PrimaryDC).name
        $ExternalTimeSvr = $Configuration.ExternalTimeSvr
        $MaxTimeDrift = $Configuration.MaxExtTimeDrift
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17041 -EntryType Information -message "START of External Time Sync Test Cycle ." -category "17041"
    }#End Begin

    Process {
        
        $PDCeTime = ([WMI]'').ConvertToDateTime((Get-WmiObject -Class win32_operatingsystem -ComputerName $PDCEmulator).LocalDateTime)
        $ExternalTime = (w32tm /stripchart /dataonly /computer:$ExternalTimeSvr /samples:1)[-1].split("[")[0]
        $ExternalTimeOutput = [Regex]::Match($ExternalTime, "\d+\:\d+\:\d+").value
        $result = (New-TimeSpan -Start $ExternalTimeOutput -End $PDCeTime).Seconds
        
        $emailOutput = "$PDCEmulator - Offset:  $result - Time:$PDCeTime  - ReferenceTime: $ExternalTimeOutput `r`n "
        
        Write-Verbose "ServerName $PDCEmulator - Offset: $result - ExternalTime: $ExternalTimeOutput - PDCE Time: $PDCeTime"
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17042 -EntryType Information -message "CHECKING External Time Sync on Server - $PDCEmulator - $emailOutput" -category "17042"

        #If result is a negative number (ie -6 seconds) convert to positive number
        # for easy comparison
        If ($result -lt 0) { $result = $result * (-1)}
        #test if result is greater than max time drift
        If ($result -gt $MaxTimeDrift) {
            
            Write-Verbose "ALERT - Time drift above maximum allowed threshold on - $server - $emailOutput"
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17040 -EntryType Warning -message "FAILURE External time drift above maximum allowed on $emailOutput `r`n " -category "17040"
            
            #attempt to automatically fix the issue
            Invoke-Command -ComputerName $server -ScriptBlock { 'w32tm /resync' }
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17045 -EntryType Information -message "REPAIR External Time Sync Remediation was attempted `r`n " -category "17045"
            $CurrentFailure = $true
            
            
            $mailParams = @{
                To = $Configuration.MailTo
                From = $Configuration.MailFrom
                SmtpServer = $Configuration.SmtpServer
                Subject = $"AD External Time Sync Alert!"
                Body = $emailOutput
                BodyAsHtml = $true
            }

            Send-MailMessage @mailParams
            #Write-Verbose "Sending Slack Alert"
            #New-SlackPost "Alert - External Time drift above max threashold - $emailOutput"

        }#end if
        If (!$CurrentFailure) {
            Write-Verbose "No Issues found in this run"
            $InError = Get-EventLog application -After (Get-Date).AddHours(-24) | where {($_.InstanceID -Match "17040")} 
            $errtext = $InError |out-string
            If ($errtext -like "*$server*") {
                Write-Verbose "Previous Errors Seen"
                #Previous run had an alert
                #No errors foun during this test so send email that the previous error(s) have cleared
                
                
                
                $alertParams = @{

                    To = $Configuration.MailTo
                    From = $Configuration.MailFrom
                    SmtpServer = $Configuration.SmtpServer
                    Subject = "AD External Time Sync - Alert Cleared!"
                    Body = "The previous alert for AD External Time Sync has now cleared."
                    BodyAsHtml = $true

                }
                
                Send-MailMessage @alertParams
                #Write-Verbose "Sending Slack Message - Alert Cleared"
                #New-SlackPost "The previous alert, for AD External Time Sync, has cleared."
            
            }#End if
       
        }#End if
    }#End Process
    
    End {
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17043 -EntryType Information -message "END of External Time Sync Test Cycle ." -category "17043"
        
    }#End End
    
}#End Function
function Test-ADInternalTimeSync {
    [CmdletBinding()]
    Param()
    <#
    .SYNOPSIS
    Monitor AD Internal Time Sync
    
    .DESCRIPTION
    This script monitors DCs for Time Sync Issues

    .EXAMPLE
    Run as a scheduled task.  Use Event Log consolidation tools to pull and alert on issues found.

    .EXAMPLE
    Run in verbose mode if you want on-screen feedback for testing
   
    .NOTES
    Authors: Mike Kanakos, Greg Onstot
    Version: 0.8.2
    Version Date: 4/18/2019
    
    Event Source 'PSMonitor' will be created

    EventID Definition:
    17030 - Failure
    17031 - Beginning of test
    17032 - Testing individual systems
    17033 - End of test
    17034 - Alert Email Sent
    17035 - Automated Repair Attempted
    #>

    Begin {
        Import-Module activedirectory
        $CurrentFailure = $null
        $null = Get-ADConfig
        $SupportArticle = $Configuration.SupportArticle
        $SlackToken = $Configuration.SlackToken
        if (!([System.Diagnostics.EventLog]::SourceExists("PSMonitor"))) {
            write-verbose "Adding Event Source."
            New-EventLog -LogName Application -Source "PSMonitor"
        }#end if
        $DClist = (Get-ADDomainController -Filter *).name  # For ALL DCs
        $PDCEmulator = (Get-ADDomainController -Discover -Service PrimaryDC).name
        $MaxTimeDrift = $Configuration.MaxIntTimeDrift

        $beginEventLog = @{
            LogName   = "Application"
            Source    = "PSMonitor"
            EventID   = 17031
            EntryType = "Information"
            Message   = "START of Internal Time Sync Test Cycle."
            Category  = "17031"
        }

        Write-eventlog  @beginEventLog

    }#End Begin

    Process {

        Foreach ($server in $DClist) {
            
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17032 -EntryType Information -message "CHECKING Internal Time Sync on Server - $server" -category "17032"
            Write-Verbose "CHECKING - $server"
            
            $OutputDetails = $null
            $Remotetime = ([WMI]'').ConvertToDateTime((Get-WmiObject -Class win32_operatingsystem -ComputerName $server).LocalDateTime)
            $Referencetime = ([WMI]'').ConvertToDateTime((Get-WmiObject -Class win32_operatingsystem -ComputerName $PDCEmulator).LocalDateTime)
            $result = (New-TimeSpan -Start $Referencetime -End $Remotetime).Seconds
            Write-Verbose "$server - Offset:  $result - Time:$Remotetime  - ReferenceTime: $Referencetime"
            
            #If result is a negative number (ie -6 seconds) convert to positive number
            # for easy comparison
            If ($result -lt 0) {
                 
                $result = $result * (-1)
            
            }
                
            #test if result is greater than max time drift
            If ($result -gt $MaxTimeDrift) {
                $emailOutput = "$server - Offset:  $result - Time:$Remotetime  - ReferenceTime: $Referencetime `r`n "
                Write-Verbose "ALERT - Time drift above maximum allowed threshold on - $server - $emailOutput"
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17030 -EntryType Warning -message "FAILURE Internal time drift above maximum allowed on $emailOutput `r`n " -category "17030"
                    
                #attempt to automatically fix the issue
                Invoke-Command -ComputerName $server -ScriptBlock { 'w32tm /resync' }
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17035 -EntryType Information -message "REPAIR Internal Time Sync remediation was attempted `r`n " -category "17035"
                CurrentFailure = $true
                Send-Mail $emailOutput
                Write-Verbose "Sending Slack Alert"
                New-SlackPost "Alert - Internal Time drift above max threashold - $emailOutput"
            }#end if
            If (!$CurrentFailure) {
                Write-Verbose "No Issues found in this run"
                $InError = Get-EventLog application -After (Get-Date).AddHours(-24) | where {($_.InstanceID -Match "17030")} 
                $errtext = $InError |out-string
                If ($errtext -like "*$server*") {
                    Write-Verbose "Previous Errors Seen"
                    #Previous run had an alert
                    #No errors foun during this test so send email that the previous error(s) have cleared
                    Send-AlertCleared
                    Write-Verbose "Sending Slack Message - Alert Cleared"
                    New-SlackPost "The previous alert, for AD Internal Time Sync, has cleared."
                    #Write-Output $InError
                }#End if

            }#End if

        }#End Foreach

    }#End Process
    
    End {
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17033 -EntryType Information -message "END of Internal Time Sync Test Cycle ." -category "17033"
    }#End End

}#End Function
Function Test-SRVRecords {

    [cmdletBinding()]
    Param()

    begin {
        Import-Module ActiveDirectory
        #Creates a global $configuration variable
        $null = Get-ADConfig
    }

    process {
        $DomainFQDN = (get-addomain).dnsroot
        $DCList = (get-adgroupmember "Domain Controllers").name
        $DCCount = (get-adgroupmember "Domain Controllers").count
        $PDCEmulator = (get-addomaincontroller -Discover -Service PrimaryDC).name
        $MSDCSZoneName = "_msdcs." + $DomainFQDN
        
        # $MSDCSZoneName = '_msdcs.bigfirm.biz'
        
        $DC_SRV_Record = '_ldap._tcp.dc'
        $GC_SRV_Record = '_ldap._tcp.gc'
        $KDC_SRV_Record = '_kerberos._tcp.dc'
        $PDC_SRV_Record = '_ldap._tcp.pdc'
        
		$DC_SRV_RecordCount = (@(Get-DnsServerResourceRecord -ZoneName $MSDCSZoneName -Name $DC_SRV_Record -RRType srv -ComputerName $PDCEmulator).count)
        $GC_SRV_RecordCount = (@(Get-DnsServerResourceRecord -ZoneName $MSDCSZoneName -Name $GC_SRV_Record -RRType srv -ComputerName $PDCEmulator).count)
        $KDC_SRV_RecordCount = (@(Get-DnsServerResourceRecord -ZoneName $MSDCSZoneName -Name $KDC_SRV_Record -RRType srv -ComputerName $PDCEmulator).count)
		
        $PDC_SRV_RecordCount = (@(Get-DnsServerResourceRecord -ZoneName $MSDCSZoneName -Name $PDC_SRV_Record -RRType srv -ComputerName $PDCEmulator).Count)

		$DCHash = @{}
		$DCHash.add($dc_SRV_Record,$dc_SRV_RecordCount)
		
		$GCHash = @{}
		$GCHash.add($gc_SRV_Record,$gc_SRV_RecordCount)
		
		$KDCHash = @{}
		$KDCHash.add($kdc_SRV_Record,$kdc_SRV_RecordCount)



        $Records = @($DCHash, $GCHash, $KDCHash)
        ForEach ($Record in $Records){
            # If ($Record -ne $DCCount){
            If ($record.values -ne $DCCount){
				$Subject = "There is an SRV record missing from DNS"
                $EmailBody = @"
        
        
        The number of records in the <font color="Red"><b> $($Record.keys) </b></font> zone in DNS does not match the number of Domain Controllers in Active Directory. Please check  DNS for missing SRV records.
		
        Time of Event: <font color="Red"><b> $((get-date))</b></font><br/>
        <br/>
        THIS EMAIL WAS AUTO-GENERATED. PLEASE DO NOT REPLY TO THIS EMAIL.
"@

            $mailParams = @{
                To = $Configuration.MailTo
                From = $Configuration.MailFrom
                SmtpServer = $Configuration.SmtpServer
                Subject = $Subject
                Body = $EmailBody
                BodyAsHtml = $true
            }

            Send-MailMessage @mailParams

            } #End if
        }#End Foreach


        If ($PDC_SRV_RecordCount -ne 1) { 
                
                $Subject = "The PDC SRV record is missing from DNS"
                $EmailBody = @"
        
        
        The <font color="Red"><b> PDC SRV record</b></font> is missing from the $MSDCSZoneName in DNS.
        Time of Event: <font color="Red"><b> $((get-date))</b></font><br/>
        <br/>
        THIS EMAIL WAS AUTO-GENERATED. PLEASE DO NOT REPLY TO THIS EMAIL.
"@

            $mailParams = @{
                To = $Configuration.MailTo
                From = $Configuration.MailFrom
                SmtpServer = $Configuration.SmtpServer
                Subject = $Subject
                Body = $EmailBody
                BodyAsHtml = $true
            }
            
            Send-MailMessage @mailParams

            } #END PDC If

    }

    end {}
}
<#A simplified re-write of a script published by Jorge de Almeida Pinto, to be used primarily for non-interactive monitoring/alerting.

The original can be found here:
https://jorgequestforknowledge.wordpress.com/2014/02/17/testing-sysvol-replication-latencyconvergence-through-powershell-update-3/

#>

function Test-SysvolReplication {
    [CmdletBinding()]
    Param()
    <#
    .SYNOPSIS
    Monitor AD SYSVOL Replication
    
    .DESCRIPTION
    Each run of the script creates a unique test object in SYSVOL on the PDCE, and tracks it's replication to all other DCs in the domain.
    By default it will query the DCs for about 60 minutes.  If after 60 loops the file hasn't repliated the test will terminate and create an alert.

    .EXAMPLE
    Run as a scheduled task.  Use Event Log consolidation tools to pull and alert on issues found.

    .EXAMPLE
    Run in verbose mode if you want on-screen feedback for testing
   
    .NOTES
    Author Greg Onstot
    This script must be run from a Win10, or Server 2016 system.  It can target older OS Versions.
    Version: 0.6.5
    Version Date: 4/18/2019
    
    Event Source 'PSMonitor' will be created

    EventID Definition:
    17000 - Failure
    17001 - Cycle Count
    17002 - Test Object not yet on DC
    17003 - Test Object on DC
    17004 - Tests didn't complete in alloted time span
    17005 - Job output
    17006 - Test Object Created
    17007 - Test Object Deleted
    17008 - 1 minute Sleep
    17009 - Alert Email Sent
    #>

    Begin {
        Import-Module activedirectory
        $null = Get-ADConfig
        $SupportArticle = $Configuration.SupportArticle
        if (![System.Diagnostics.EventLog]::SourceExists("PSMonitor")) {
            write-verbose "Adding Event Source."
            New-EventLog -LogName Application -Source "PSMonitor"
        }
        $continue = $true
        $CurrentFailure = $false
        $domainname = (Get-ADDomain).dnsroot
        $DCList = (Get-ADDomainController -Filter *).name
        $SourceSystem = (Get-ADDomain).pdcemulator
        [int]$MaxCycles = $Configuration.MaxSysvolReplCycles
    }
    
    Process {
        if (Test-NetConnection $SourceSystem -Port 445) {
            Write-Verbose 'PDCE is online'
            $TempObjectLocation = "\\$SourceSystem\SYSVOL\$domainname\Scripts"
            $tempObjectName = "sysvolReplTempObject" + (Get-Date -f yyyyMMddHHmmss) + ".txt"
            $objectPath = "\\$SourceSystem\SYSVOL\$domainname\Scripts\$tempObjectName"
            "...!!!...TEMP OBJECT TO TEST AD REPLICATION LATENCY/CONVERGENCE...!!!..." | Out-File -FilePath $($TempObjectLocation + "\" + $tempObjectName)
            $site = (Get-ADDomainController $SourceSystem).site

            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17006 -EntryType Information -message "CREATE SYSVOL Test object - $tempObjectName  - has been created on $SourceSystem in site - $site" -category "17006"
            Start-Sleep 30
            If (!(Test-Path -Path $objectPath)){
                Write-Verbose "Object wasn't created properly, trying a second time"
                $tempObjectName = "sysvolReplTempObject" + (Get-Date -f yyyyMMddHHmmss) + ".txt"
                $objectPath = "\\$SourceSystem\SYSVOL\$domainname\Scripts\$tempObjectName"
                "...!!!...TEMP OBJECT TO TEST AD REPLICATION LATENCY/CONVERGENCE...!!!..." | Out-File -FilePath $($TempObjectLocation + "\" + $tempObjectName)
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17006 -EntryType Information -message "CREATE SYSVOL Test object attempt Number 2 - $tempObjectName  - has been created on $SourceSystem in site - $site" -category "17006"
                Start-Sleep 30
            }

            If (!(Test-Path -Path $objectPath)){
                Write-Verbose "Object wasn't created properly after 2 tries, exiting..."
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17000 -EntryType Error -message "FAILURE to write SYSVOL test object to PDCE - $SourceSystem  in site - $site" -category "17000"
                #Write-Verbose "Sending Slack Alert"
                #New-SlackPost "Alert - FAILURE to write SYSVOL test object to PDCE - $SourceSystem  in site - $site"
                Exit
            }
            
            $startDateTime = Get-Date
            $i = 0
        }
        else {
            Write-Verbose 'PDCE is offline.  You should really resolve that before continuing.'
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17000 -EntryType Error -message "FAILURE to connect to PDCE - $SourceSystem  in site - $site" -category "17000"
            #Write-Verbose "Sending Slack Alert"
            #New-SlackPost "Alert - FAILURE to connect to PDCE - $SourceSystem  in site - $site"
            Exit
        }
        
        While ($continue) {
            $i++
            Write-Verbose 'Sleeping for 1 minute.'
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17008 -EntryType Information -message "SLEEPING SYSVOL test for 1 minute" -category "17008"
            Start-Sleep 60
            $replicated = $true
            Write-Verbose "Cycle - $i"
            Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17001 -EntryType Information -message "CHECKING SYSVOL ADRepl Cycle $i" -category "17001"
        
            Foreach ($dc in $DCList) {
                $site = (Get-ADDomainController $dc).site
                if (Test-NetConnection $dc -Port 445) {
                    Write-Verbose "Online - $dc"
                    $objectPath = "\\$dc\SYSVOL\$domainname\Scripts\$tempObjectName"
                    $connectionResult = "SUCCESS"
                }
                else {
                    Write-Verbose "!!!!!OFFLINE - $dc !!!!!"
                    $connectionResult = "FAILURE"
                    Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17000 -EntryType Error -message "FAILURE to connect to DC - $dc in site - $site" -category "17000"
                }
                # If The Connection To The DC Is Successful
                If ($connectionResult -eq "SUCCESS") {
                    If (Test-Path -Path $objectPath) {
                        # If The Temp Object Already Exists
                        Write-Verbose "     - Object [$tempObjectName] Now Does Exist In The NetLogon Share"
                        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17003 -EntryType Information -message "SUCCESS SYSVOL Object Successfully replicated to  - $dc in site - $site" -category "17003"
                    }
                    Else {
                        # If The Temp Object Does Not Yet Exist
                        Write-Verbose "     - Object [$tempObjectName] Does NOT Exist Yet In The NetLogon Share"
                        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17002 -EntryType Information -message "PENDING SYSVOL Object replication pending for  - $dc in site - $site" -category "17002"
                        $replicated = $false
                    }
                }
        		
                # If The Connection To The DC Is Unsuccessful
                If ($connectionResult -eq "FAILURE") {
                    Write-Verbose "     - Unable To Connect To DC/GC And Check For The Temp Object..."
                    Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17000 -EntryType Error -message "FAILURE to connect to DC - $dc in site - $site" -category "17000"
                }
            }
            If ($replicated) {
                $continue = $false
            } 
        
            If ($i -gt $MaxCycles) {
                $continue = $false
                #gather event history to see which DC did, and which did not, get the replication
                $list = Get-EventLog application -After (Get-Date).AddHours(-2) | where {($_.InstanceID -Match "17002") -OR ($_.InstanceID -Match "17003") -OR ($_.InstanceID -Match "17006")} 
                $RelevantEvents = $list |Select InstanceID,Message |Out-String
                
                Write-Verbose "Cycle has run $i times, and replication hasn't finished.  Need to generate an alert."
                Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17004 -EntryType Warning -message "INCOMPLETE SYSVOL Test cycle has run $i times without the object succesfully replicating to all DCs" -category "17004"
                $Alert = "In $domainname - the SYSVOL test cycle has run $i times without the object succesfully replicating to all DCs.  
                Please see the following support article $SupportArticle to help investigate
                
                Recent history:
                $RelevantEvents
                "
                $CurrentFailure = $true
                Send-Mail $Alert
                #Write-Verbose "Sending Slack Alert"
                #New-SlackPost "Alert - Incomplete SYSVOL Replication Cycle in the domain: $domainname"
            } 
        }	
    }
    
    End {
        # Show The Start Time, The End Time And The Duration Of The Replication
        $endDateTime = Get-Date
        $duration = "{0:n2}" -f ($endDateTime.Subtract($startDateTime).TotalSeconds)
        $output = "`n  Start Time......: $(Get-Date $startDateTime -format "yyyy-MM-dd HH:mm:ss")"
        $output = $output + "`n  End Time........: $(Get-Date $endDateTime -format "yyyy-MM-dd HH:mm:ss")"
        $output = $output + "`n  Duration........: $duration Seconds"
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17005 -EntryType Information -message "END of SYSVOL Test cycle - $output" -category "17005"
        
        Write-Verbose "`n  Start Time......: $(Get-Date $startDateTime -format "yyyy-MM-dd HH:mm:ss")"
        Write-Verbose "  End Time........: $(Get-Date $endDateTime -format "yyyy-MM-dd HH:mm:ss")"
        Write-Verbose "  Duration........: $duration Seconds"
        
        # Delete The Temp Object On The RWDC
        Write-Verbose "  Deleting Temp Text File..."
        Remove-Item "$TempObjectLocation\$tempObjectName" -Force
        Write-Verbose "  Temp Text File [$tempObjectName] Has Been Deleted On The Source System"
        Write-eventlog -logname "Application" -Source "PSMonitor" -EventID 17007 -EntryType Information -message "DELETED SYSVOL Test object - $tempObjectName  - has been deleted." -category "17007"

        If (!$CurrentFailure){
            Write-Verbose "No Issues found in this run"
            $InError = Get-EventLog application -After (Get-Date).AddHours(-2) | where {($_.InstanceID -Match "17000") -or ($_.InstanceID -Match "17004")} 
            If ($InError) {
                Write-Verbose "Previous Errors Seen"
                #Previous run had an alert
                #No errors foun during this test so send email that the previous error(s) have cleared
                Send-AlertCleared
                #Write-Verbose "Sending Slack Message - Alert Cleared"
                #New-SlackPost "The previous alert, for AD SYSVOL Replication, has cleared."
                #Write-Output $InError
            }#End if
        }#End if
    }#End End
}
$PublicFunctions = 'Copy-Scripts', 'Get-ADConfig', 'Get-ADLastBackupDate', 'Get-DCDiskSpace', 'Restore-PSADHealthConfig', 'Set-PSADHealthConfig', 'Test-ADConfigMailer', 'Test-ADObjectReplication', 'Test-ADReplication', 'Test-ADServices', 'Test-DCsOnline', 'Test-ExternalDNSServers', 'Test-ADExternalTimeSync', 'Test-ADInternalTimeSync', 'Test-SRVRecords', 'Test-SYSVOL-Replication'
