Import-module .\tw-ps-module.psm1 -Force
# ----------------- Misc Functions ------------------------
Function Send-TCPMessage { 
    Param ( 
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()] 
            [string] 
            $EndPoint
        , 
            [Parameter(Mandatory=$true, Position=1)]
            [int]
            $Port
        , 
            [Parameter(Mandatory=$true, Position=2)]
            [string]
            $Message
    ) 
    Process {
        # Setup connection 
        $IP = [System.Net.Dns]::GetHostAddresses($EndPoint) 
        $Address = [System.Net.IPAddress]::Parse($IP) 
        $Socket = New-Object System.Net.Sockets.TCPClient($Address,$Port) 
    
        # Setup stream writer 
        $Stream = $Socket.GetStream() 
        $Writer = New-Object System.IO.StreamWriter($Stream)

        # Write message to stream
        $Message | foreach-object {
            $Writer.WriteLine($_)
            $Writer.Flush()
        }
    
        # Close connection and stream
        $Stream.Close()
        $Socket.Close()
    }
}
function TEPolicySyslogSender{
    Param($TEServer,$TEPass,$TEUser,$PolicyName,$NodeGroupName,$TestState,$Hours,$SyslogServer,$SyslogPort)
    Get-TEAPILogin -sslIgnore $true -teserver $TEServer -tepass $tepass -teuser $TEUser
    If($null -eq $TestState){
        $Messages = Get-TEPolicyResultByNodeGroupSyslogMessageFormat -PolicyName $PolicyName -NodeGroupName $NodeGroupName
    }
    Else
    {
        if($null -ne $hours){
            Get-TEPolicyResultByNodeGroupSyslogMessageFormatFilteredByStateAndHours -PolicyName $PolicyName -NodeGroupName $NodeGroupName -TestState $TestState -Hours $Hours
        }
        Else{
            $Messages = Get-TEPolicyResultByNodeGroupSyslogMessageFormatFiltered -PolicyName $PolicyName -NodeGroupName $NodeGroupName -TestState $TestState
        }
    }
    if($null -ne $Messages){
        $Messages | foreach-object{
            $DateStamp = [DateTime]::UtcNow | get-date -Format "yyyy-MM-ddTHH:mm:ssZ"
            $MessageToSend = "<134>1 $DateStamp" + $_
            Write-host $MessageToSend
            Send-TCPMessage -Message $MessageToSend -EndPoint $SyslogServer -port $SyslogPort
        }
    }
}
