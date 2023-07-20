<#
  .SYNOPSIS
    A set of commandlets that allows for easy management of Tripwire Enterprise
  .DESCRIPTION
    A set of commandlets that allows for easy management of Tripwire Enterprise via PowerShell
  .EXAMPLE
    #TODO N/A
  .NOTES
    
#>
#Requires -Version 3.0
<#
=========================================
CHANGELOG:
=========================================
2019-02-13 - Chris Hudson - Tripwire Professional Services - Initial release version
2019-07-21 - Chris Hudson - Tripwire Professional Services - Code refactoring
2019-11-10 - Chris Hudson - added New commandlets
2021-10-18 - Chris Hudson - added New commandlets and code refactoring 
2022-03-03 - Chris Hudson - added New commandlets and code refactoring 
2023-06-14 - Chris Hudson - added New commandlets and code refactoring 
#>
# Title:     TE Object Management
# Author:    Tripwire Customer Services
# Copyright: ©2023 Tripwire
# Version:   2.1.0
#
# THIS SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR
# FITNESS FOR A PARTICULAR PURPOSE, AND/OR NONINFRINGEMENT.
#
# This script is not supported under any Tripwire standard support program or service.
# The script is provided AS IS without warranty of any kind. Tripwire further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Tripwire, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for
# any damages whatsoever (including, without limitation, damages for loss of business profits,
# business interruption, loss of business information, or other pecuniary loss) arising out of
# the use of or inability to use the sample or documentation, even if Tripwire has been advised
# of the possibility of such damages.
#
# WITHOUT LIMITING THE GENERALITY OF THE FOREGOING, TRIPWIRE HAS NO OBLIGATION TO INDEMNIFY OR
# DEFEND RECIPIENT AGAINST CLAIMS RELATED TO INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS.
# ----------------------------------------------------
# General Setup
#-----------------------------------------------------------[Functions]------------------------------------------------------------
# -------------------- API Access -------------------------
function Set-IgnoreSSL{
    <#
    .SYNOPSIS
    Disables SSL validation (useful where certificates are not trusted/the self signed certificate is used in TE) - note that this is not recommended
    .DESCRIPTION
    Disables SSL validation (useful where certificates are not trusted/the self signed certificate is used in TE) - note that this is not recommended
    .EXAMPLE
    Set-IgnoreSSL $true
    .NOTES
#>
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}
function Get-TERESTLogin{
    <#
    .SYNOPSIS
    Establishes a login session with the TE REST API 
    .DESCRIPTION
    Establishes a login session with the TE REST API 
    .EXAMPLE
    Get-TERESTLogin -TEUser "myUser" -TEPass "MyPassword" -TEServer "localhost"
    .EXAMPLE
    Get-TERESTLogin -TEUser "myUser" -TEPass "MyPassword" -TEServer "localhost" -sslIgnore $true
    .NOTES
    #>
    param($sslIgnore,$TEServer,$TEUser,$TEPass)
    if($sslIgnore){Set-IgnoreSSL}
    if($null -eq $TEServer){$TEServer = Read-host "Please enter the hostname/ip address of a TE server"}
    if($null -eq $TEServer){Write-host "TE Server not specified, assuming localhost run on 127.0.0.1";$teserver = "127.0.0.1"}
    if($null -eq $TEUser){$TEUser = Read-host "Please enter a username"}
    if($null -eq $TEUser){Write-Error "TE user not specified"; break}
    if($null -eq $TEPass){Read-host "Please enter the TE server password for the user: $TEUser" -maskinput}
    if($null -eq $TEPass){Write-Error "TE Password not specified"; break}
    $securePasssword = ConvertTo-SecureString $tepass -AsPlainText -Force
    $Creds = New-Object System.Management.Automation.PSCredential($teuser,$securePasssword)
    $Uri = "https://$teserver/api/v1/"
    Write-debug "Connecting to $uri"
    Write-debug "as $teuser"
    # TLS 1.2 is generally considered the norm here, but can be overriden if required.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $CSRF = try{Invoke-RestMethod -Uri ($Uri+'csrf-token') -Method Get -Credential $Creds -ContentType 'application/json' -Headers $headers -SessionVariable ActiveSessionVariable}
    catch{Write-error "Failed to connect to REST API API to login"}
    $headers = @{};
    $headers.Add($CSRF.tokenName, $CSRF.tokenValue)
    $headers.Add("X-Requested-With", "XMLHttpRequest")
    $headers | Out-String -stream | Write-Debug
    If (!$headers.CSRFToken) 
        {
        Write-Error "Error logging in to retrieve CSRF token - please check the URL, credentials provided and access"
        break
        }
    else{
        Write-debug "Logged in to REST API and added CSRF token to header for reuse"
        }
    Write-debug "Setting URI,Headers and ActiveSessionVariable for reuse"
    Set-Variable -Name URI -Value $Uri -Scope Global
    Set-Variable -Name headers -Value $headers -Scope Global
    Set-Variable -Name ActiveSessionVariable -Value $ActiveSessionVariable -Scope Global
    Write-Verbose "Login complete. Please ensure you close your PowerShell session or request a logoff to clear credentials!"
}
function Get-TESOAPLogin{
    <#
    .SYNOPSIS
    Establishes a login session with the TE SOAP API 
    .DESCRIPTION
    Establishes a login session with the TE SOAP API 
    .EXAMPLE
    Get-TESOAPLogin -TEUser "myUser" -TEPass "MyPassword" -TEServer "localhost"
    .EXAMPLE
    Get-TESOAPLogin -TEUser "myUser" -TEPass "MyPassword" -TEServer "localhost" -sslIgnore $true
    .NOTES
#>
    param($sslIgnore,$TEServer,$TEPass,$TEUser)
    If ($sslIgnore -eq $True){Set-IgnoreSSL}
    if($null -eq $TEServer){$TEServer = Read-host "Please enter the hostname/ip address of a TE server"}
    if($null -eq $TEServer){Write-Warning "TE Server not specified, assuming localhost run on 127.0.0.1";$teserver = "127.0.0.1"}
    if($null -eq $TEUser){$TEUser = Read-host "Please enter a username"}
    if($null -eq $TEUser){Write-Error "TE user not specified"; break}
    if($null -eq $TEPass){Read-host "Please enter the TE server password for the user: $TEUser" -maskinput}
    if($null -eq $TEPass){Write-Error "TE Password not specified"; break}
    $temppath = ".\soappacket.txt"
    $soappacket =  @"
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="https://localhost/twservice/wsdl/1">
    <soapenv:Header/>
    <soapenv:Body>
    <ns:loginArgs>
    <username>$teuser</username>
    <password>$tepass</password>
    </ns:loginArgs>
    </soapenv:Body>
    </soapenv:Envelope>
"@
    try{$soappacket | Out-File $temppath -force -Encoding utf8}catch{Write-error "Failed to write to local path, this may cause issues with SOAP API access later"}
    $header = @{"SOAPAction" = "login"}
    $tesoap = Invoke-WebRequest -Method Post -Uri "https://$teserver/twservice/soap" -InFile $temppath -ContentType "text/xml" -Headers $header -SessionVariable sesvar
    Set-Variable -Name "TEServer" -Value $teserver -Scope Global
    Set-Variable -name "SESVAR" -Value $sesvar -Scope Global
    Remove-Item $temppath
    if ($tesoap.content -match 'status\=\"authenticated\"'){Write-debug "Logged in to SOAP API"}else{Write-error "SOAP API Log in failed"}
    }
function Get-TERESTLogOut{
    try
        {
        Invoke-RestMethod -Uri ($uri+"logout") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        Remove-Variable URI,headers,ActiveSessionVariable -Scope Global
        }
    Catch
        {
        Write-Warning "Error logging off - please ensure you close your session and ensure you are logged off via the TE web console"
        exit
        }
}
function Get-TEAVLogin{
    <#
    .SYNOPSIS
    Establishes a login session with the TE Asset View API 
    .DESCRIPTION
    Establishes a login session with the TE Asset View API 
    .EXAMPLE
    Get-TEAVLogin -TEUser "myUser" -TEPass "MyPassword" -TEServer "localhost"
    .EXAMPLE
    Get-TEAVLogin -TEUser "myUser" -TEPass "MyPassword" -TEServer "localhost" -sslIgnore $true
    .NOTES
#>
    param($sslIgnore,$TEServer,$TEPass,$TEUser)
    If ($sslIgnore -eq $True){Set-IgnoreSSL}
    if($null -eq $TEServer){$TEServer = Read-host "Please enter the hostname/ip address of a TE server"}
    if($null -eq $TEServer){Write-Warning "TE Server not specified, assuming localhost run on 127.0.0.1";$teserver = "127.0.0.1"}
    if($null -eq $TEUser){$TEUser = Read-host "Please enter a username"}
    if($null -eq $TEUser){Write-Error "TE user not specified"; break}
    if($null -eq $TEPass){Read-host "Please enter the TE server password for the user: $TEUser" -maskinput}
    if($null -eq $TEPass){Write-Error "TE Password not specified"; break}
    Write-debug "Setting values for TE Asset View Logins"
    $securePasssword = ConvertTo-SecureString $tepass -AsPlainText -Force
    $TECreds = New-Object System.Management.Automation.PSCredential($teuser,$securePasssword)
    $TEAVURI = "https://$teserver/assetview/api/"
    Set-Variable -Name "TECreds" -Value $TECreds -Scope Global
    Set-Variable -Name "TEAVURI" -Value $TEAVUri -Scope Global
    Write-debug "Get-TEAVLogin completed"
}
function Get-TESOAPLogoff{
    $soappacket =  @"
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="https://localhost/twservice/wsdl/1">
    <soapenv:Header/>
    </soapenv:Body/>
    </soapenv:Envelope>
"@
    $temppath = "soappacket.txt"
    $soappacket | Out-File $temppath  -force -Encoding utf8
    $header = @{"SOAPAction" = "logout"}
    $tesoap = Invoke-WebRequest -Method Post -Uri "https://$teserver/twservice/soap" -InFile $temppath -ContentType "text/xml" -Headers $header -WebSession $sesvar 
    Write-debug $tesoap.Content
    Remove-Item $temppath
    if ($tesoap.content -match 'status\=\"loggedOut\"'){Write-Information "Logged off of SOAP API" -ForegroundColor Green}else{Write-error "SOAP Log off failed"}
}
function Get-TEAPILogin{
    param([Parameter(Mandatory=$true)]
            [boolean]$sslIgnore,
            [Parameter(Mandatory=$true)]
            [string]$teserver,
            [Parameter(Mandatory=$true)]
            [string]$tepass,
            [Parameter(Mandatory=$true)]
            [string]$teuser)
    Get-TESOAPLogin -sslIgnore $sslIgnore -teserver $teserver -tepass $tepass -teuser $teuser
    Get-TERESTLogin -sslIgnore $sslIgnore -teserver $teserver -tepass $tepass -teuser $teuser
    Get-TEAVLogin -sslIgnore $sslIgnore -teserver $teserver -tepass $tepass -teuser $teuser
}
function Get-TEAPILogoff{
    Get-TESOAPLogoff -credentials Get-Credential
    try{
        Remove-Variable Creds,AVURI,sesvar,teserer,headers,uri,activesessionvariable
        }
    catch
        {
        Write-Warning "Expected login variable(s) not found - maybe you haven't logged in before running this command? If not, please ensure you close the PowerShell session to clear credential values"
        }
}
function Get-TEAPILoginStatus{
    If(!$ActivesessionVariable)
        {
            Write-Error "Please login using Get-APILogin first"; 
            return $false
        }
    else
        {
        try
            {
            # Try a test connecting to the REST API
            $APITest = Invoke-RestMethod -Uri ($uri+"status") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
            Write-debug $APITest.hostname
            return $true
            }
        catch
            {
            # Try logging back in again with details already in the session
            try
                {
                    Get-TEAPILogin -sslIgnore $true -teserver $teserver -tepass $tepass -teuser $teuser
                    return $true
                }
            catch
                {
                    Write-error "Session with TE failure"
                    return $false
                }
            }
        }
}
function mergeJson ($target, $source) {
        $source.psobject.Properties | foreach-object {
            if ($_.TypeNameOfValue -eq 'System.Management.Automation.PSCustomObject' -and $target."$($_.Name)" ) 
            {
                merge $target."$($_.Name)" $_.Value
                Write-debug $_.Name 
                Write-debug $_.Value
            }
            else {
                $target | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value -Force
                Write-debug $_.Name 
                Write-debug $_.Value
            }
        }
    }
# -------------------- REST API Methods ---------------------------
# --------------------- Nodes -----------------------------
function Get-TENodes{
    param($type,$name,$make,$tag,$oid,$model,[int]$maxSeverity,$id,$ipaddress,[int]$elementCount)
    <#
    .SYNOPSIS
    Gathers TE Nodes with optional filtering
    .DESCRIPTION
    Gathers TE Nodes with optional filtering for:
    - type
    - name
    - make
    - model
    - maxSeverity (maximum change severity)
    - ipaddress
    - id (object id)
    - elementcount (useful for finding )
    .EXAMPLE
    Get-TENodes
    Returns all nodes
    .EXAMPLE
    Get-TENodes -tag "Status:Monitoring Enabled"
    Gets nodes with the tag Monitoring Enabled 
    .EXAMPLE
    Get-TENodes -name "dc"
    Get's nodes with the name dc - note this is not case specific but is otherwise an exact match
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $page = 0
        $params = @{}
        if($type){$params["type"] = $type}
        if($name){$params["ic_name"] = $name}
        if($ipaddress){$params["ipaddress"] = $ipaddress}
        if($id){$params["id"] = $id}
        if($make){$params["make"] = $make}
        if($model){$params["model"] = $model}
        if($elementCount){$params["elementCount"] = $elementCount}
        if($maxSeverity){$params["maxSeverity"] = $maxSeverity}
        if($oid){$params["oid"] = $oid}
        if($tag){
            if(($tag.split(":")).count -eq 2)
                {
                    Write-debug "Tag format is correct" 
                $params["tag"] = $tag
                }
        else{
            Write-Error "Tag format is incorrect - please use the format 'tagsetname:tagname' - tag filter won't be applied" }
            }
        do{    
                $newnodeset = Invoke-RestMethod -Uri ($Uri+"nodes?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
                $page = $page + 10
                $nodes += $newnodeset
        }while($newnodeset.count -ne 0)
        return $Nodes
        }
}
function Get-TENodesinNodeGroup{
    Param($NodeGroupName,$id)
    <#
    .SYNOPSIS
    Gathers TE nodes in a particular node group
    .DESCRIPTION
    Gathers TE nodes in a particular node group

    .EXAMPLE
    Get-TENodesinNodeGroup -NodeGroupName "Windows"
    Returns nodes within the smart node/node group "Windows"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {   
        $params = @{}
        if($NodeGroupName){$params["name"] = $NodeGroupName}
        if($id){$params["id"] = $id}
        $NodeGroup = Invoke-RestMethod -Uri ($uri+"nodegroups") -Method Get -ContentType 'Application/json' -Body $Params -Headers $headers -WebSession $ActiveSessionVariable
        $NodeGroupMembers = Invoke-RestMethod -Uri ($uri+"nodegroups/"+$nodegroup[0].id+"/descendantNodes") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        $NodeGroupMembers | foreach-object{
            $nodes += @(Get-TENodes -id $_.id)
        }
        Return $Nodes
    }
}
function Get-TENodesUnchecked{
    Param([Parameter(Mandatory=$true)]$previoushours,$EnabledOnly)
    <#
    .SYNOPSIS
    Gathers TE nodes that have the "last checked" time greater than the specified number of hours
    .DESCRIPTION
    Gathers TE nodes that have the "last checked" time greater than the specified number of hours, optionally filtering the results to only include enabled nodes
    .EXAMPLE
    Get-TENodesUnchecked -previoushours '24' -enabledOnly $true
    Gets nodes with that haven't been checked in the last 24 hours (excluding disabled nodes)
    .EXAMPLE
    Get-TENodesUnchecked -previoushours '24' 
    Gets nodes with that haven't been checked in the last 24 hours (including disabled nodes)
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {
        # Convert hours to a date time
        $checkdate = (Get-Date).AddHours(-$previoushours)
        $checkdate = '{0:yyyy-MM-ddThh:mm:s.000Z}' -f $checkdate
        Write-debug "Checking for devices unchecked since $checkdate"
        $Nodes = Invoke-RestMethod -Uri ($uri+"nodes") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        $nodes = $nodes | Where-Object {$_.lastCheck -lt $checkdate}
        if($EnabledOnly -eq $true){$nodes = $nodes | Where-Object {$_.isDisabled -eq $False}}
        return $Nodes
    }
}
function Get-TENodeGroups{
    param($Name)
    <#
    .SYNOPSIS
    Gathers TE node groups
    .DESCRIPTION
    Gathers TE node groups with optional filtering by name

    .EXAMPLE
    Get-TENodeGroups
    Returns all node groups
    .EXAMPLE
    Get-TENodeGroups -name "Monitoring Enabled"
    Gets the node group "Monitoring Enabled"

    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
    $params = @{}
    if($Name){$params["name"] = $Name}
    try
        {$nodegroups = Invoke-RestMethod -Uri ($Uri+'nodegroups/') -Method Get -Body $params -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $nodegroups
        }
    catch
        {Write-Error "Error getting node group data - please check the connection and try again"}
    }
}
function Get-TENodeParentGroups{
    param($NodeName)
    <#
    .SYNOPSIS
    Gets a TE node's parent groups
    .DESCRIPTION
    Returns an array of a node's parent groups (including Smart Node Tags and Node Group).
    NB Node name must be unique as only one node can be returned.

    .EXAMPLE
    Get-TENodeParentGroups -nodename "myNode"
    Returns parent node groups for a node named myNode

    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {
        $parentgroupnames = @()
        $node = Get-TENodes -name $NodeName
        if($node.id.count -eq 1)
            {
            $id = $node.id
            Write-Information "Getting data for "$id "," $NodeName
            try{
                $parents = Invoke-RestMethod -Uri ($Uri+"nodes/$id/parentGroups") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
                $parents | ForEach-Object{
                # Get bottom object to find the "closest" tag
                $count = $_.path.name.Count - 1
                $parentgroupnames += $_.path.name[$count]}
                return $parentgroupnames
                }
            catch{Write-error "Failed to get Node parents"}
            }
        else{Write-error "Node not found or multiple nodes found"}
    }
}
function Compare-TENodesToIPList{
   param( [parameter(mandatory)]$inputfile, [parameter(mandatory)]$matchesoutfile,[parameter(mandatory)]$missingoutfile)
    <#
    .SYNOPSIS
    Compares TE nodes against a list file of IP addresses to find missing and found nodes
    .DESCRIPTION
    Compares TE nodes against a list file of IP addresses to find missing and found nodes
    Input file must contain IP addresses seperate by new lines

    .EXAMPLE
    Compare-TENodesToIPList -inputfile "C:\mylistofnodes.txt" -matchesoutfile "C:\mylistofFoundnodes.txt" -missingoutfile "C:\mylistofMissingnodes.txt"
    Takes a list of nodes from the input file (mylistofnodes.txt) and compares them to the TE nodes, outputing a mylistoffoundnodes.txt showing nodes that were found in TE and a mylistofmissingnodes.txt showing any IP's that were not found in TE.

    .NOTES
    #>
   if($true -eq (Get-TEAPILoginStatus))
   {
    $checklist = Get-Content $inputfile
    $checklist | ForEach-Object {
            $result = Get-TENodes -ip $_
            if($null -ne $result)
                {
                Write-host "Match found for $_" -ForegroundColor Green
                if($null -ne $matchesoutfile)
                    {
                    $_ | Out-File -Append -FilePath $matchesoutfile
                    }
                }
                else
                    {
                    Write-Host "No match found for $_" -ForegroundColor DarkYellow
                    if(null -ne $$missingoutfile)
                        {
                        $_ | Out-File -Append -FilePath $missingoutfile
                        }
                    }
            $result = $null
            }
    }
}
# -------------------- Versions ---------------------------
function Get-TEVersionLatest{
    param($RuleName,$NodeName,$sha1,$sha256,$md5,$sha512,$id,$approvalid,$changeType,$elementId,$nodeID,$ruleId,$severity)
    <#
    .SYNOPSIS
    Gathers the latest TE element versions 
    .DESCRIPTION
    Gathers TE element versions with optional (but highly recommended!) filtering for:
    - rulename
    - nodename
    - sha1, md5, sha256, sha512
    - approvalid, promotionComment
    - ruleid, nodeid, elementid
    - severity
    - versionid
    .EXAMPLE
    Get-TEVersionLatest -severity 10000
    Returns all high severity versions 
    .EXAMPLE
    Get-TEVersionLatest -approvalid "CHG123"
    Returns all versions with the approval ID CHG123
    .EXAMPLE
    Get-TEVersionLatest -nodename "teconsole" -rulename "Network Interface Configuration" -severity 10000
    Get's versions with severity 10000, for the rule "Network Interface Configuration" on the node "teconsole"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $page = 0
        $params = @{}
        if($RuleName){$params["ruleName"] = $RuleName}
        if($severity){$params["severity"] = $severity}
        if($sha1){$params["sha1"] = $sha1}
        if($sha256){$params["sha256"] = $sha256}
        if($md5){$params["md5"] = $md5}
        if($sha512){$params["sha512"] = $sha512}
        if($id){$params["id"] = $id}
        if($approvalid){$params["approvalid"] = $approvalid}
        if($promotionComment){$params["promotionComment"] = $promotionComment}
        if($changeType){$params["changeType"] = $changeType}
        if($elementId){$params["elementId"] = $elementId}
        if($nodeID){$params["nodeID"] = $nodeID}
        if($nodeName){$params["nodeLabel"] = $nodeName}

        if($ruleId){$params["ruleId"] = $ruleId}
        if($ruleName){$params["ruleName"] = $ruleName}
        do{ 
            $newversionset = Invoke-RestMethod -Uri ($Uri+"versions/latest?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
            $page = $page + 10
            $versions += $newversionset
        }while($newversionset.count -ne 0)
         return $Versions
    }
}
function Get-TEVersionContent{
    param($id)
    <#
    .SYNOPSIS
    Gathers a TE element version's content
    .DESCRIPTION
    Gathers a TE element version's content. Binary content is not supported.
    .EXAMPLE
    Get-TEVersionContent -id "-1y2p0ij32e8ce:-1y2p0ij30t9ao"
    Returns the content of a version with the id of -1y2p0ij32e8ce:-1y2p0ij30t9ao
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $Versions = Invoke-RestMethod -Uri ($Uri+"versions/$id/content") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $Versions
    }
}
function Get-TEVersionAttributes{
    param($id)
    <#
    .SYNOPSIS
    Gathers a TE element version's attributes
    .DESCRIPTION
    Gathers a TE element version's attributes. 
    .EXAMPLE
    Get-TEVersionAttributes -id "-1y2p0ij32e8ce:-1y2p0ij30t9ao"
    Returns the content of a version with the id of -1y2p0ij32e8ce:-1y2p0ij30t9ao
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $Versions = Invoke-RestMethod -Uri ($Uri+"versions/$id/attributes") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $Versions
    }
}
function Get-TEVersionAuditRecords{
    param($id)
    <#
    .SYNOPSIS
    Gathers a TE element version's audit records
    .DESCRIPTION
    Gathers a TE element version's audit records. 
    .EXAMPLE
    Get-TEVersionAuditRecords -id "-1y2p0ij32e8ce:-1y2p0ij30sdbs"
    Returns the audit details of a version with the id of -1y2p0ij32e8ce:-1y2p0ij30sdbs
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        if($true -eq (Get-TEAPILoginStatus)){
        $Versions = Invoke-RestMethod -Uri ($Uri+"versions/$id/audit") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $Versions
        }
    }
}
# ---------------------- TASKS ----------------------------
function Get-TETask{
    param($Name,$Enabled,$id,$nodeid,$ruleid,$type)
    <#
    .SYNOPSIS
    Gathers TE tasks
    .DESCRIPTION
    Gathers TE task(s) with optional filtering for:
    - name
    - enabled (true/false)
    - id
    - nodeid
    - ruleid
    - type ()
    .EXAMPLE
    Get-TETask -name "Test Task"
    Returns the task details of a task with the name of "Test Task"
    .EXAMPLE
    Get-TETask -nodeId "-1y2p0ij32e8ay:-1y2p0ij32e78n"
    Returns the task details of a task with the node scope including the ID "-1y2p0ij32e8ay:-1y2p0ij32e78n" - note that this must be the node group if the task is scoped to a group rather than individual rule(s)
    .EXAMPLE
    Get-TETask -ruleId "-1y2p0ij32e8ay:-1y2p0ij32e78n"
    Returns the task details of a task with the rule scope including the ID "-1y2p0ij32e8ay:-1y2p0ij32e78n" - note that this must be the rule group if the task is scoped to a rule group rather than individual rule(s)
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $page = 0
        $params = @{}
        if($Name){$params["name"] = $Name}
        if($Enabled){$params["enabled"] = $Enabled}
        if($id){$params["id"] = $id}
        if($nodeid){$params["nodeId"] = $nodeid}
        if($ruleid){$params["ruleId"] = $ruleid}
        if($type){$params["type"] = $type}
        do{ 
            $taskset = Invoke-RestMethod -Uri ($Uri+"tasks?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
            $page = $page + 10
            $tasks += $taskset
        }while($taskset.count -ne 0)
    return $tasks
    }
}
function Get-TETaskGroup{
    param($Name,$ID)
    <#
    .SYNOPSIS
    Gathers TE Task groups
    .DESCRIPTION
    Gathers TE task(s) with optional filtering for:
    - name
    - id
    .EXAMPLE
    Get-TETaskGroup -name "Test Task Group"
    Returns the task group details of a task group with the name of "Test Task Group"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $params = @{}
        if($Name){$params["name"] = $Name}
        if($id){$params["id"] = $id}
        $taskg = Invoke-RestMethod -Uri ($Uri+'taskgroups') -Method Get -Body $Params -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $taskg
    }
}
#TODO: Update this to reflect current commandlet function designs
function New-TETaskGroupLink{
    param($ItemToLink,$TargetTaskPath)
    If(!$ActivesessionVariable){Write-Host "Please login using Get-TE-REST-Login first";break}
    $destination = Get-TETaskGroup -name $TargetTaskPath
    $destination = $destination.id
    try
        {
        $source = Get-TETask -Name $ItemToLink
        }
    catch
        {
        $source = Get-TETaskGroup -name $TargetTaskPath
        }
    $source = $source.id
    # Link to new destination
    $taskmove = Invoke-RestMethod -Uri ($Uri+'taskgroups/'+$destination+'/links/'+$source) -Method POST -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
    return $taskmove
}
#TODO: Update this to reflect current commandlet function designs
function Remove-TETaskGroupLink{
    param($ItemToUnLink,$GroupToUnlinkFrom)
    If(!$ActivesessionVariable){Write-Host "Please login using Get-TE-REST-Login first";break}
    $destination = Get-TETaskGroup -name $GroupToUnlinkFrom
    $destination = $destination.id
    try
        {
        $source = Get-TETask -Name $ItemToUnLink
        }
    catch
        {
        $source = Get-TETaskGroup -name $ItemToUnLink
        }
    $source = $source.id
    # Link to new destination
    $taskmove = Invoke-RestMethod -Uri ($Uri+'taskgroups/'+$destination+'/links/'+$source) -Method DELETE -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
    return $taskmove
}
function New-TECheckTaskManual{
    param([parameter(mandatory)]$TaskName,[parameter(mandatory)]$NodeGroupName, [parameter(mandatory)]$RuleGroupName,[parameter(mandatory)]$Enabled)
    <#
    .SYNOPSIS
    Creates a manual (unscheduled) TE check task
    .DESCRIPTION
    Creates a manual (unscheduled) TE check task for a given nodegroup and rulegroup. Note that tasks are setup with a 1 hour timeout by default
    .EXAMPLE
    New-TECheckTaskManual -TaskName "My Test Task" NodeGroupName "Microsoft Windows Server 2019" RuleGroupName "OS Configuration Auditing" -enabled $true
    Creates a task that runs the OS Configuration Auditing rules on the Node Group Microsoft Windows Server 2019 entitled test task
    .EXAMPLE
    New-TECheckTaskManual -TaskName "My Test Task" NodeGroupName "Microsoft Windows Server 2019" RuleGroupName "OS Configuration Auditing" -enabled $false
    Creates a disabled task that runs the OS Configuration Auditing rules on the Node Group Microsoft Windows Server 2019 entitled test task
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $nodegroupoid = Get-TENodeGroups | Where-Object {$_.name -eq $NodeGroupName}
        $rulegroupoid = Get-TERuleGroups | Where-Object {$_.name -eq $RuleGroupName}
        if($nodegroupoid.id.count -gt 1){Write-Warning "Multiple matching rule groups found, using first found"}
        elseif($nodegroupoid.id.count -eq 0){Write-error "Node group not found"; break}
        if($rulegroupoid.id.count -gt 1){Write-Warning "Multiple matching rule groups found, using first found"}
        elseif($rulegroupoid.id.count -eq 0){Write-error "Rule group not found"; break}
        $nodegroupoid = $nodegroupoid[0].id
        $rulegroupoid = $rulegroupoid[0].id
        #$schedule = @{type="Manually"} 
        $json = @{description="";enabled=$Enabled;name=$TaskName;nodeId=$nodegroupoid;schedule=@{type="Manually"} ;ruleId=$rulegroupoid;timeout=1;timeoutMillis=3600000;type="Check Rule Task"} | ConvertTo-Json
        Write-debug $json
        try{$newtask = Invoke-RestMethod -Uri ($Uri+'tasks') -Method POST -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $json}
        catch{Write-error "Failed to create task"}
        return $newtask
    }
}
function Invoke-TETaskRun{
    param([parameter(mandatory)]$TaskName)
    <#
    .SYNOPSIS
    Executes a TE Task (starts a run)
    .DESCRIPTION
    Executes a TE Task (starts a run)
    .EXAMPLE
     Invoke-TETaskRun -TaskName "My Test Task"
    Runs a check task called "My Test Task"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $tasktorun = Get-TETask -Name $TaskName
        if($tasktorun.id.count -gt 1){Write-Warning "Multiple matching tasks  found, using first found"}
        elseif($tasktorun.id.count -eq 0){Write-error "Task not found"; break}
        $tasktorun = $tasktorun.id
        $json = @{requestData=@{taskId="$tasktorun"}} | ConvertTo-Json
        Write-debug $json
        $taskrun = Invoke-RestMethod -Uri ($Uri+'tasks/executeTaskRequests') -Method POST -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $json
        return $taskrun
    }
}
function Get-TETaskTargetNodes{
    param([parameter(mandatory)]$Taskname)
    <#
    .SYNOPSIS
    Gets a list of nodes scoped to a task
    .DESCRIPTION
    Gets a list of nodes scoped to a task
    .EXAMPLE
    Get-TETaskTargetNodes -TaskName "My Test Task"
    Returns a list of nodes in scope for the check task called "My Test Task"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $task = Get-TETask -Name $taskname
        if($task.id.count -gt 1){Write-Warning "Multiple matching tasks found, using first found"}
        elseif($task.id.count -eq 0){Write-error "Task not found"; break}
        $taskid = $task[0].id
        Write-debug "Getting task details"
        $taskdetails = Invoke-RestMethod -Uri ($Uri+'tasks/'+$taskid+'/targetableNodes') -Method GET -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $taskdetails
    }
}
function Get-TETaskRunNodeResults{
    param([parameter(mandatory)]$Taskname,[boolean]$PrettyPrint)
    <#
    .SYNOPSIS
    Gets the results of a TE task run
    .DESCRIPTION
    Gets the results of a TE task run
    .EXAMPLE
    Get-TETaskRunNodeResults -TaskName "My Test Task"
    Returns the results for the check task called "My Test Task"
    .EXAMPLE
    Get-TETaskRunNodeResults -TaskName "My Test Task" -PrettyPrint $true
    Returns the results for the check task called "My Test Task" in a more screen readable format with colour coding for errors and/or timeouts
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $task = Get-TETask -Name $taskname
        if($task.id.count -gt 1){Write-Warning "Multiple matching tasks found, using first found"}
        elseif($task.id.count -eq 0){Write-error "Task not found"; break}
        $taskid = $task[0].id
        Write-debug "Getting task details"
        Write-debug "Getting $taskid"
        $taskdetails = Invoke-RestMethod -Uri ($Uri+'tasks/'+$taskid+'/nodeStatus') -Method GET -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
        if($PrettyPrint -eq $true)
            {
            $taskdetails | ForEach-Object{
                Write-host "*****************************************" -ForegroundColor Blue
                Write-host "Check Task Status Details"
                $node = Get-TENodes -id $_.nodeId | Select-Object name,ipAddresses,description,hasFailures,make,model
                Write-Host "Device name:   " $node.name -ForegroundColor DarkGreen
                Write-Host "IP addresses:  " $node.ipAddresses
                Write-Host "Description:   " $node.description
                Write-Host "Make:          " $node.make
                Write-Host "Model:         " $node.model
                Write-Host "Task Outcomes"
                if($_.haserrors -eq $False){Write-host "--Has errors:   " $_.hasErrors -ForegroundColor Green}else{Write-host "--Has errors:" $_.hasErrors -ForegroundColor red}
                if($_.hasTimeout -eq $False){Write-host "--Has timeout:  " $_.hasTimeout -ForegroundColor Green}else{Write-host "--Has timeout:" $_.hasTimeout -ForegroundColor red}
                Write-host "--Start time:   " $_.StartTime
                Write-host "--End time:     " $_.endTime
                Write-host "--Last updated: " $_.LastUpdated
            }
        }
        else{
            return $taskdetails
        }
    }
}
function Get-TETaskRunResult{
    param([parameter(mandatory)]$taskid)
    <#
    .SYNOPSIS
    Gets the results of an API invoked task run
    .DESCRIPTION
    Gets the results of an API invoked task run (using ID returned as a result of running an Invoke-TETaskRun)
    .EXAMPLE
    Get-TETaskRunResult -taskid "2"
    Gets the results of an API invoked task run with the ID of 2
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $taskrun = Invoke-RestMethod -Uri ($Uri+'tasks/executeTaskRequests/'+$taskid) -Method GET -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $taskrun
    }
}
function Remove-TETask{
    param($Name,$ID)
    <#
    .SYNOPSIS
    Removes a TE Task
    .DESCRIPTION
    Removes a TE Task based on either
    - id
    - name
    .EXAMPLE
    Remove-TETask -Name "My Test Task"
    Removes a task called "My Test Task"
    .EXAMPLE
    Remove-TETask -id "-1y2p0ij32e8at:-1y2p0ij2wozym"
    Removes a task with the id -1y2p0ij32e8at:-1y2p0ij2wozym
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        if($Name){$tasktoremove = Get-TETask -Name $Name}
        elseif($ID){$tasktoremove = Get-TETask -id $ID}
        else{Write-Error "Please specify either a name or an ID"}
        if($tasktoremove.id.count -gt 1){Write-Warning "Multiple matching tasks found, using first found"}
        elseif($tasktoremove.id.count -eq 0){Write-error "Task not found"; break}
        $tasktoremove = $tasktoremove.id
        $taskremove = Invoke-RestMethod -Uri ($Uri+'tasks/'+$tasktoremove) -Method DELETE -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $taskremove
    }
}
# -------------------- REST API ---------------------------
# ---------------------- Log Entry ----------------------------
function New-TELogEntry{
    param([parameter(mandatory)]$LogText,$Level)
    <#
    .SYNOPSIS
    Creates a TE (System) log entry 
    .DESCRIPTION
    Adds a system log entry to the TE Log Manager
    .EXAMPLE
    New-TELogEntrySimple -LogText "Test" -Level "INFO"
    Creates a system log entry with the text "Test" as INFO level
    .EXAMPLE
    New-TELogEntrySimple -LogText "Another test"
    Creates a system log entry with the text "Another Test" as INFO level
    .EXAMPLE
    New-TELogEntrySimple -LogText "Another test" -Level "ERROR"
    Creates a system log entry with the text "Error Alert " as ERROR level
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        if($level -notin ("INFO","ERROR")){Write-Warning "Level must be either INFO or ERROR - this event will be logged as INFO"; $Level = "INFO"}
        $body = @{level=$LEVEL;message="$logtext";type="System"}| ConvertTo-Json
        Write-debug $body
        $logentry = Invoke-RestMethod -Uri ($Uri+'logMessages') -Method POST -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $body
        return $logentry
    }
}
function Get-TELogs{
    param($Level,$messagecontent,$starttime,$endtime,$type,$user,$id,$maxlogcount)
    <#
    .SYNOPSIS
    Gets TE log entries
    .DESCRIPTION
    Retrieves TE log entries with optional filters for level (error, unknown, info), message content, start and end time, type, user and message id
    .EXAMPLE
    Get-TELogs -level "ERROR"
    Gets all log entries with the level of ERROR
    .EXAMPLE
    Get-TElogs -level "ERROR" -starttime "2020-01-01T00:00:00.000Z" -endtime "2020-01-02T00:00:00.000Z"
    Gets all log entries with the level of ERROR between 1st Jan 2020 and 2nd Jan 2020
        .EXAMPLE
    Get-TElogs -level "ERROR" -starttime "2020-01-01T00:00:00.000Z" -endtime "2020-01-02T00:00:00.000Z" -maxlogcount 100
    Gets the first 100 log entries with the level of ERROR between 1st Jan 2020 and 2nd Jan 2020
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $params = @{}
        $page = 0
        $TEDateRegex = "^([0-9]{4})-?(1[0-2]|0[1-9])-?(3[01]|0[1-9]|[12][0-9])"
        if($level -notin ("INFO","ERROR","UNKNOWN")){Write-Warning "Level must be either INFO, ERROR or UNKNOWN"}else{$params["level"] = $level}
        if($messagecontent){$params["sub_message"] = $messagecontent}
        if($id){$params["id"] = $id}
        if($starttime -match $TEDateRegex -and $endtime -match $TEDateRegex){$params["timeRange"] = "$starttime,$endtime"}else{Write-error "Invalid date"; break}
        if($type){$params["type"] = $type}
        if($user){$params["user"] = $user}
        if($maxlogcount){$params["pageLimit"] = $maxlogcount}else{$params["pageLimit"] = 10}
        do{    
            $logentry = Invoke-RestMethod -Uri ($Uri+"logMessages?pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
            $page = $page + 10
            $logs += $logentry
    }while($logentry.count -ne 0)
    return $logs
    }
}
function New-TERadiusLog{
    param([parameter(mandatory)]$LogText,$Level,[parameter(mandatory)]$NodeName)
    <#
    .SYNOPSIS
    Creates a TE (RADIUS) log entry 
    .DESCRIPTION
    Adds a system log entry to the TE Log Manager
    .EXAMPLE
    New-TELogEntrySimple -LogText "Test" -Level "INFO" -nodename "Example Node"
    Creates a system log entry with the text "Test" as INFO level
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        if($level -notin ("INFO","ERROR")){Write-Warning "Level must be either INFO or ERROR - this event will be logged as INFO"; $Level = "INFO"}
        $nodetologagainst = Get-TENodes -name $NodeName
        if($nodetologagainst.id.count -gt 1){Write-Warning "Multiple matching nodes found, using first found"}
        elseif($nodetologagainst.id.count -eq 0){Write-error "No node found - no log message will be created"; break}
        Write-debug $nodetologagainst
        $nodeid = $nodetologagainst[0].id
        $body = @{level="INFO";message= "$logtext";type="RADIUS";objects=@("$nodeid")}| ConvertTo-Json
        Write-debug $body
        $logentry = Invoke-RestMethod -Uri ($Uri+'logMessages') -Method POST -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $body
        return $logentry
    }
}
# ---------------------- Rules ----------------------------
function Get-TERuleGroups{
    param($Name,$ID)
    <#
    .SYNOPSIS
    Gathers TE rule groups
    .DESCRIPTION
    Gathers TE rule groups based on filters 
    - name
    - id
    .EXAMPLE
    Get-TERuleGroups -name "Example Rule Group"
    Finds a TE rule group named "Example Rule Group"
    .EXAMPLE
    Get-TERuleGroups
    Returns all TE Rule groups
    .EXAMPLE
    Get-TERuleGroups -id "-1y2p0ij32e8ay:-1y2p0ij32e78n"
    Returns the TE Rule group with the id -1y2p0ij32e8ay:-1y2p0ij32e78n
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $params = @{}
        if($Name){$params["name"] = $Name}
        if($id){$params["id"] = $id}
        $rulegroup = Invoke-RestMethod -Uri ($Uri+'rulegroups') -Method Get -body $Params -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $rulegroup
    }
}
function New-TERuleGroup{
    Param([parameter(mandatory)]$RuleGroupName,$RuleGroupDescription,$RuleGroupParent)
    <#
    .SYNOPSIS
    Creates a new Rule Group
    .DESCRIPTION
    Creates a new Rule Group
    .EXAMPLE
    New-TERuleGroup -RuleGroupName "Test Group Name" -RuleGroupDescription "Test description" -RuleGroupParent "Linux OS Rule Group"
    Creates a new rule group called "Test Group Name" with the description "Test description" and adds it to the "Root Rule Group"
    .EXAMPLE
    New-TERuleGroup -RuleGroupName "Test Group Name" 
    Creates a new rule group called "Test Group Name" in the (default) "Root Rule Group"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $json = @{description="$RuleGroupDescription";name="$RuleGroupName"} | ConvertTo-Json
        $parentrulegroup = Invoke-RestMethod -Uri ($Uri+'rulegroups/?name='+$RuleGroupParent) -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        if(!$parentrulegroup){$parentrulegroup = Invoke-RestMethod -Uri ($Uri+'rulegroups/?name=Root Rule Group') -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable}
        $ruleGrouptoadd = Invoke-RestMethod -Uri ($Uri+'rulegroups') -Method POST -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $json
        # Move to final path
        $newrulegroup = $ruleGrouptoadd[0].id
        $parentrulegroup = $parentrulegroup[0].id
        $result = Invoke-RestMethod -Uri ($Uri+"rulegroups/"+$parentrulegroup+"/links/"+$newrulegroup) -Method POST -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $result
    }
}
function New-TERuleGroupLink{
    param([parameter(mandatory)]$RuleGroupName,[parameter(mandatory)]$NewParentRuleGroup)    
    <#
    .SYNOPSIS
    Links a rule group to another rule group
    .DESCRIPTION
    Links a rule group to another rule group
    .EXAMPLE
    New-TERuleGroupLink -RuleGroupName "Test Group Name" -NewParentRuleGroup "Linux OS Rule Group"
    Links the Test Group Name to the Linux OS Rule Group
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $parentrulegroup = Invoke-RestMethod -Uri ($Uri+'rulegroups/?name='+$NewParentRuleGroup) -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        if($parentrulegroup.id.count -gt 1){Write-Warning "Multiple parent rule groups found, using first found"}
        elseif($parentrulegroup.id.count -eq 0){Write-error "No parent rule group found - no link will be created"; break}
        $rulegroup = Invoke-RestMethod -Uri ($Uri+'rulegroups/?name='+$RuleGroupName) -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        if($rulegroup.id.count -gt 1){Write-Warning "Multiple rule groups to link found, using first found"}
        elseif($rulegroup.id.count -eq 0){Write-error "No rule group found - no link will be created"; break}
        $rulegroupid = $rulegroup[0].id
        $parentrulegroupid = $parentrulegroup[0].id
        try
            {
            $result = Invoke-RestMethod -Uri ($Uri+"rulegroups/"+$parentrulegroupid+"/links/"+$rulegroupid) -Method POST -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
            return $result
            }
        catch
            {
            Write-Error "Error linking TE rule groups: is the group maybe already linked?"
            }
    }
}
function New-TERuleLink{
    param([parameter(mandatory)]$RuleName,[parameter(mandatory)]$ParentRuleGroup)    
    <#
    .SYNOPSIS
    Links a rule to a rule group
    .DESCRIPTION
    Links a rule to a rule group
    .EXAMPLE
     New-TERuleLink -RuleName "Test Rule Name" -ParentRuleGroup "Linux OS Rule Group"
    Links the Test Rule Name to the Linux OS Rule Group
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $ParentRuleGroup = Get-TERuleGroups -Name $ParentRuleGroup
        if($parentrulegroup.id.count -gt 1){Write-Warning "Multiple parent rule groups found, using first found"}
        elseif($parentrulegroup.id.count -eq 0){Write-error "No parent rule group found - no link will be created"; break}
        $Rule = Get-TERule -Name $RuleName
        if($rulegroup.id.count -gt 1){Write-Warning "Multiple rules to link found, using first found"}
        elseif($rulegroup.id.count -eq 0){Write-error "No rules found - no link will be created"; break}
        $ParentRuleGroupId = $ParentRuleGroup[0].id
        $RuleID = $Rule[0].id
        try
            {
            $result = Invoke-RestMethod -Uri ($Uri+"rulegroups/"+$ParentRuleGroupId+"/links/"+$RuleID) -Method POST -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
            return $result
            }
        catch
            {
            Write-Error "Error linking TE rule: is the rule maybe already linked?"
            }
    }
}
function Remove-TERuleGroup{
    param([parameter(mandatory)]$RuleGroupName)
    <#
    .SYNOPSIS
    Removes a TE rule group
    .DESCRIPTION
    Removes a TE rule group
    .EXAMPLE
    Remove-TERuleGroup -RuleGroupName "Test Group Name"
    Removes a rule group called "Test Group Name"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $rulegroup = Get-TERuleGroups -Name $RuleGroupName
        if($rulegroup.id.count -gt 1){Write-Warning "Multiple rule groups to delete found, using first found"}
        elseif($rulegroup.id.count -eq 0){Write-error "No rule group found - can not delete"; break}
        $rulegroupid = $rulegroup.id
        $result =  Invoke-RestMethod -Uri ($Uri+'rulegroups/'+$rulegroupid) -Method DELETE -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $result
    }
}
function Get-TERule{
    param($Name,$id,[boolean]$isRealTime,$type,$elementName,[int]$severity,$description)
    <#
    .SYNOPSIS
    Gathers TE rules
    .DESCRIPTION
    Gathers TE rule based on filters 
    - name
    - id
    .EXAMPLE
    Get-TERule -name "Example Rule"
    Finds a TE rule named "Example Rule"
    .EXAMPLE
    Get-TERule
    Returns all TE Rules
    .EXAMPLE
    Get-TERule -id "-1y2p0ij32e8ay:-1y2p0ij32e78n"
    Returns the TE Rule  with the id -1y2p0ij32e8ay:-1y2p0ij32e78n
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $page = 0
        $params = @{}
        if($Name){$params["name"] = $Name}
        if($id){$params["id"] = $id}
        if($elementName){$params["elementName"] = $elementName}
        if($type){$params["type"] = $type}
        if($description){$params["description"] = $description}
        if($severity){$params["severity"] = $severity}
        if($isRealTime){$params["isRealTime"] = $isRealTime}
        do{    
            $ruleset = Invoke-RestMethod -Uri ($Uri+"rules?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
            $page = $page + 10
            $rules += $ruleset
            }
        while($ruleset.count -ne 0)
        return $rules
    }
}
function Rename-TERule{
    param([parameter(mandatory)]$RuleName,[parameter(mandatory)]$NewRuleName)
    <#
    .SYNOPSIS
    Renames a rule
    .DESCRIPTION
    Renames a rule
    .EXAMPLE
    Rename-TERule -NewRuleName "New Name" -RuleName "blah"
    Renames the rule "blah" to "New Name"
    .EXAMPLE
    Rename-TERule -NewRuleName "New Name" -id "-1y2p0ij32e8ay:-1y2p0ij32e78n"
    Renames the rule with the ID -1y2p0ij32e8ay:-1y2p0ij32e78n to "New Name"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        if(!$RuleID)
            {
            $rule = Get-TERule -Name $RuleName
            if($rule.id.count -gt 1){Write-Warning "Multiple rules to delete found, using first found only"}
            elseif($rule.id.count -eq 0){Write-error "No rule found - can not rename"; break}
            $ruleid = $rule[0].id
            }
        else
            {
            $rule = Get-TERule -id $id
            if($rule.id.count -gt 1){Write-Warning "Multiple rules to delete found, using first found only"}
            elseif($rule.id.count -eq 0){Write-error "No rule found - can not rename"; break}
            $ruleid = $rule[0].id
            }
        $json = @{name="$NewRuleName"} | ConvertTo-Json
        write-debug $json
        $result = Invoke-RestMethod -Uri ($Uri+'rules/'+$ruleid) -Method PUT -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $json
        return $result
    }
}
function Get-TERuleParentGroups{
    param([parameter(mandatory)]$Name)
    <#
    .SYNOPSIS
    Gets a TE rule's parent groups
    .DESCRIPTION
    Returns an array of a rules's parent groups (including Smart Node Tags and Node Group).
    NB Rule name must be unique as only one node can be returned.

    .EXAMPLE
    Get-TERuleParentGroups -Name "rulename"
    Returns parent node groups for a rule named rulename

    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {
        $parentgroupnames = @()
        $rule = Get-TERUle -name $Name
        if($rule.id.count -eq 1)
            {
            $id = $rule.id
            Write-Information "Getting data for "$id "," $rule
            try{
                $parents = Invoke-RestMethod -Uri ($Uri+"rules/$id/parentGroups") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
                if($parents)
                    {
                    $Parents | ForEach-Object{
                        # Get bottom object to find the "closest" tag
                        try{
                            $count = $_.path.name.Count - 1
                            if($count -ne 0)
                                {
                                $parentgroupnames += $_.path.name[$count]
                                }
                            else
                                {
                                $parentgroupnames += $_.path.name
                                }
                            }
                        catch
                            {Write-debug "Empty path found"}
                        }
                    return $parentgroupnames
                    }
                else{write-error "No parent groups found"}
                }
                catch
                    {Write-error "Failed to get rule parents"}
                }
                else{Write-error "Rule not found or multiple rules found"}
    }
}
function Remove-TERuleLink{
    param([parameter(mandatory)]$RuleGroupName,[parameter(mandatory)]$RuleName)
    <#
    .SYNOPSIS
    Removes a TE rule link
    .DESCRIPTION
    Removes a TE rule link
    .EXAMPLE
    Remove-TERuleLink -GroupName "Test Group Name" -RuleName "My Rule"
    Removes a link between the rule "My Rule" and the rule group "Test Group Name"
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $Rule = Get-TERule -Name $RuleName
        if($Rule.id.count -gt 1){Write-Warning "Multiple rules to unlink found, using first found"}
        elseif($Rule.id.count -eq 0){Write-error "No rule found - can not unlink"; break}
        $RuleID = $Rule.id
        $rulegroup = Get-TERuleGroups -Name $RuleGroupName
        if($rulegroup.id.count -gt 1){Write-Warning "Multiple rule groups to unlink found, using first found"}
        elseif($rulegroup.id.count -eq 0){Write-error "No rule group found - can not unlink"; break}
        $rulegroupid = $rulegroup.id
        $result =  Invoke-RestMethod -Uri ($Uri+"rulegroups/$rulegroupid/links/$RuleID/") -Method DELETE -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $result
    }
}
function Move-TERule{
    param([parameter(mandatory)]$ItemToMove,[parameter(mandatory)]$DestinationGroup,[boolean]$RemoveOtherLinks)
    <#
    .SYNOPSIS
    Moves a TE Rule
    .DESCRIPTION
    Moves a TE Rule to an existing rule group
    .EXAMPLE
    Move-TERule -RuleToMove "My Rule" -DestinationRuleGroup "My Rule Group"
    Moves a rule called "My Rule" to a rule group called "My Rule Group"
    .EXAMPLE
    Move-TERule -RuleToMove "My Rule" -DestinationRuleGroup "My Rule Group" -RemoveOtherLinks $true
    Moves a rule called "My Rule" to a rule group called "My Rule Group" and removes any other existing links for that rule
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
    Write-Warning "NB: This will unlink the rule from any other current parent rule groups"
    # Get current parent rule group before moving
    $Rule = Get-TERule -Name $ItemToMove
    if($Rule.id.count -gt 1){Write-Warning "Multiple rules to move found, using first found"}
    elseif($Rule.id.count -eq 0){Write-error "No rule found - can not delete"; break}
    $RuleID = $Rule.id
    $RuleGroup = Get-TERuleGroups -Name $DestinationGroup
    if($RuleGroup.id.count -gt 1){Write-Warning "Multiple rule groups to delete found, using first found"}
    elseif($RuleGroup.id.count -eq 0){Write-error "No rule group found - can not delete"; break}
    $RuleGroupID = $RuleGroup.id

    # link to desired destination rule group
    try{$result = Invoke-RestMethod -Uri ($Uri+"rulegroups/"+$RuleGroupID+"/links/"+$RuleID) -Method POST -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable}catch{Write-Error "Failed to link to parent ";break}
    # Remove from original rule groups
    if($RemoveOtherLinks -eq $true){
            $Parents = Get-TERuleParentGroups -Name $ItemToMove
            # Remove our new destination rule group
            $parents = $parents | Where-Object {$_ -ne $DestinationGroup}
            $parents | ForEach-Object{
                try{Remove-TERuleLink -RuleGroupName $_ -RuleName $ItemToMove}
                catch{Write-Error "Failed to remove rule from parent rule group "+$parenttostrip.name+"(ID: "+$parenttostrip.id+")"}
                }
            }
    return $result
    }
}
function New-TERuleExternal{
    Param([parameter(mandatory)]$RuleGroupName,[parameter(mandatory)]$RuleName,$RuleDescription,$TrackingID)
    <#
    .SYNOPSIS
    Creates a new External Rule
    .DESCRIPTION
    Creates a new External Rule
    .EXAMPLE
    New-TERuleExternal -RuleGroupName "Test Group Name" -RuleDescription "Test description" -RuleName "My New External Rule"
    Creates a new rule called "My New External Rule" with the description "Test description" and adds it to the "Test Group Name" rule group
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $RuleGroupParent = Get-TERuleGroups -Name $RuleGroupName
        $json = @{description="$RuleDescription";name="$RuleName";type="External Rule";trackingId="$TrackingID"} | ConvertTo-Json
        $newRule = Invoke-RestMethod -Uri ($Uri+'rules') -Method Post -Body $json -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        try{Move-TERule -ItemToMove $RuleName -DestinationGroup $RuleGroupName}catch{Write-Warning "Failed to move rule to final destination group - rule may have not been created or is in Unlinked Group"}
        return $newRule
    }
}
function New-TERuleExternalVersion{
    Param([parameter(mandatory)]$RuleName,[parameter(mandatory)]$ElementName,[parameter(mandatory)]$Content,[parameter(mandatory)]$NodeName,$Severity,$ChangeType)
    <#
    .SYNOPSIS
    Adds a new External Rule Element Version
    .DESCRIPTION
    Adds a new External Rule Element Version
    .EXAMPLE
    New-TERuleExternalVersion -RuleName "My New External Rule" -ElementName "My New Element" -Content "My New Content"
    Adds a new element called "My New Element" with the content "My New Content" to the rule "My New External Rule"
    .EXAMPLE
    New-TERuleExternalVersion -RuleName "My New External Rule" -ElementName "My New Element" -Content "My New Content" -severity 1
    Adds a new element called "My New Element" with the content "My New Content" to the rule "My New External Rule" with a severity of 1
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $Rule = Get-TERule -Name $RuleName
        $Node = Get-TENodes -Name $NodeName
        if($null -eq $changeType -or $changeType -notin @("MODIFIED","ADDED","REMOVED")){$ChangeType = "MODIFIED"}
        if($Rule.id.count -gt 1){Write-Warning "Multiple rules found, using first found"}
        elseif($Rule.id.count -eq 0){Write-error "No rule found - can not create element version"; break}
        if($Node.id.count -gt 1){Write-Warning "Multiple nodes found, using first found"; }
        elseif($Node.id.count -eq 0){Write-error "No node found - can not create element version"; break}
        $RuleId = $Rule[0].id
        $NodeId = $Node[0].id
        $versionContent=(@{content="$Content";elementName="$ElementName";severity="$Severity";timeDetected=(Get-Date -UFormat '+%Y-%m-%dT%H:%M:%S.000Z');changeType=$ChangeType});
        $payload =@{nodeId=$Nodeid;ruleId = $Ruleid; versions = @($versionContent);}
        $json =(convertTo-json -Depth 5 -InputObject @{"requestData"=$payload;})
        Write-debug $json
        $newElementVersion = Invoke-RestMethod -Uri ($Uri+'versions/createVersionRequests') -Method Post -Body $json -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $newElementVersion
    }
}
# -------------------- REST API ---------------------------
# -------------------- Policies ---------------------------
function Get-TEPolicies{
    param($Name,$ID)
    <#
    .SYNOPSIS
    Gathers TE policies with optional filtering
    .DESCRIPTION
    Gathers TE policies with optional filtering for:
    - name
    - id (object id)
    .EXAMPLE
    Get-TEPolicies
    Returns all policies
    .EXAMPLE
    Get-TEPolicies -Name "My Example Policy"
    Gets the My Example Policy policy
    .EXAMPLE
    Get-TEPolicies -ID "youroid"
    Returns a policy with the id of youroid
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $page = 0
        $params = @{}
        if($name){$params["name"] = $name}
        if($id){$params["id"] = $id}
        do{    
            $policyset = Invoke-RestMethod -Uri ($Uri+"policies?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
            $page = $page + 10
            $policies += $policyset
        }while($policyset.count -ne 0)
        return $policies
    }
}
function Get-TEPolicyTest{
    param($Name,$ID,$Type,$RuleID,$PolicyID,$PolicyName)
    <#
    .SYNOPSIS
    Gathers TE policy tests with optional filtering
    .DESCRIPTION
    Gathers TE policy tests with optional filtering for:
    - name
    - type
    - id (object id)
    - associated with rule id (useful for finding related records)
    - policyName
    - policyID (object id)
    .EXAMPLE
    Get-TENodes
    Returns all nodes
    .EXAMPLE
    Get-TENodes -tag "Status:Monitoring Enabled"
    Gets nodes with the tag Monitoring Enabled 
    .EXAMPLE
    Get-TENodes -name "dc"
    Get's nodes with the name dc - note this is not case specific but is otherwise an exact match
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $page = 0
        $params = @{}
        if($name){$params["name"] = $name}
        if($id){$params["id"] = $id}
        if($RuleID){
            if(($RuleID.split(",")) -gt 1){Write-Warning "Multiple rule IDs found, using first only";$RuleID = $RuleID.split(",")[0]}
            $params["rules"] = $RuleID
            }
        if($Type){
            if($type -notin @("Content Test","Attribute Test","Windows ACL Test")){Write-Error "Invalid policy test type, must be either Content Test, Attribute Test, Windows ACL Test";break}
            $params["type"] = $Type
            }
        if($policyID){$params["policyId"] = $policyID}
        if($policyName){
            $Policy = Get-TEPolicies -Name $PolicyName
            if($Policy.id.count -eq 0){Write-Error "Policy ($PolicyName)not found";break}
            if($policy.id.count -gt 1){Write-Warning "Multiple policies found, using first only"}
            $PolicyID = $Policy[0].id
            $params["policyId"] = $policyID
        }
        do{    
            $policyset = Invoke-RestMethod -Uri ($Uri+"policytests?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
            $page = $page + 10
            $policies += $policyset
        }while($policyset.count -ne 0)
        return $policies
    }
}
function Get-TEPolicyUnknownResultCSV{
    <#
    .SYNOPSIS
    Gets policy test results which are unknown
    .DESCRIPTION
    Gets policy test results which are unknown
    .EXAMPLE
     Get-TEPolicyUnknownResultCSV
    Returns all unknown policy test results
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
    $unknown = Invoke-RestMethod -Uri ($Uri+'policytestresults/unknownTestResults') -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
    $Policies = Get-TEPolicies
    $Nodes = Get-TENodes
    $PolicyTests = Get-TEPolicyTest
    $UnknownResultCSV = "PolicyName,PolicyTestName,NodeName`n"
    $unknown | foreach-object {
        $PolicyTestID = $_.policyTestID
        $PolicyID = $_.policyID
        $NodeID = $_.nodeID
        $node = $Nodes | Where-Object {$_.id -eq $NodeID}
        $Policy = $policies | where-object {$_.id -eq $PolicyID}
        $PolicyTest = $PolicyTests | where-object {$_.id -eq $PolicyTestID}
        $UnknownResultCSV += $Policy.Name+","+$PolicyTest.Name+","+$Node.name+"`n"
    }
    return $UnknownResultCSV
    }
}
function Get-TEPolicyTestParentGroups{
    param([parameter(mandatory)]$Name)
    <#
    .SYNOPSIS
    Gets a TE policytest's parent groups
    .DESCRIPTION
    Returns an array of a policy test's parent groups
    NB Test name must be unique as only one test can be returned.

    .EXAMPLE
    Get-TEPolicyTestParentGroups -Name "policytestname"
    Returns parent groups for a policy test named policytestname
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {
        $parentgroupnames = @()
        $PolicyTest = Get-TEPolicyTest -name $Name
        if($PolicyTest.id.count -eq 1)
            {
            $id = $PolicyTest.id
            Write-Information "Getting data for "$id "," $PolicyTest
            try{
                $parents = Invoke-RestMethod -Uri ($Uri+"policytests/$id/parentGroups") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
                if($parents)
                    {
                    $Parents | ForEach-Object{
                        try{
                            $count = $_.path.name.Count - 1
                            if($count -ne 0)
                                {
                                $parentgroupnames += $_.path.name[$count]
                                }
                            else
                                {
                                $parentgroupnames += $_.path.name
                                }
                            }
                        catch
                            {Write-debug "Empty path found"}
                        }
                    return $parentgroupnames
                    }
                else{write-error "No parent groups found"}
                }
                catch
                    {Write-error "Failed to get policy test parents"}
                }
                else{Write-error "Policy test not found or multiple policy tests with the same name found"}
    }
}
function Get-TEPolicyTestRemediationDetails{
    param($Name,$ID)
    <#
    .SYNOPSIS
    Gets a TE policytest's remediation advice
    .DESCRIPTION
    Returns the remediation advice for a given policy test
    .EXAMPLE
    Get-TEPolicyTestRemediationDetails -Name "policytestname"
    Returns remediation advice for a policy test named policytestname
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {
    try{
        $PolicyTest =  Get-TEPolicyTest -Name $Name -ID $ID
        if($PolicyTest.id.count -gt 1){Write-Warning "Multiple policy tests found, using first found"}
        elseif($PolicyTest.id.count -eq 0){Write-Error "No policy test found";break}
        $PolicyTestID = $PolicyTest[0].id
        try{
            $policytest = Invoke-RestMethod -Uri ($Uri+'policytests/'+$PolicyTestID+"/remediation") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
            return $policytest
        }
        catch
        {Write-error "Failed to get policy remediation advice"}
    }catch
    {Write-error "Failed to get policy test"}
    }
}
function Get-TEPolicyNodeScope{
    param($PolicyName,$PolicyID,[boolean]$ResolveNames)
    <#
    .SYNOPSIS
    Gets a TE policies node scope
    .DESCRIPTION
    Gets a TE policies node scope
    .EXAMPLE
    GEt-TEPolicyNodeScope -PolicyName "policyname"
    Returns the node scope for a policy named policyname
    .EXAMPLE
    GEt-TEPolicyNodeScope -PolicyName "policyname" -ResolveNames $true
    Returns the node scope for a policy named policyname and resolves the node names
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {
        try{
            $policy = Get-TEPolicies -Name $PolicyName -PolicyID $PolicyID
            if($Policy.id.count -lt 1){Write-Error "Failed to find policy"; break}
            elseif($Policy.id.count -gt 1){Write-Warning "Multiple policies found, using first found"}
            $policyid = $policy[0].id
            $policynodescope = Invoke-RestMethod -Uri ($Uri+'policies/'+$policyid+'/includedNodes') -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
            if ($ResolveNames) {
                $policynodescope | ForEach-Object{
                    $PolicyScopeNode = Get-TENodes -id $_
                    Write-debug $PolicyScopeNode
                    return $PolicyScopeNode
                    }
            }
            else{
                return $policynodescope
            }
        }
        catch{
            Write-error "Error extracting policy node list"
        }
    }
}
function Get-TEPolicyTestResult{
    param($PolicyTestName,$NodeName,$State,$PolicyTestId,$nodeID,$PolicyName)
    <#
    .SYNOPSIS
    Gets the latest results of a policy test
    .DESCRIPTION
    Gets the results of a policy test
    .EXAMPLE
    Get-TEPolicyTestResult -policytestname "policytestname" -nodename "nodename"
    Returns the latest result of a policy test named policytestname on a node named nodename
    .EXAMPLE
    Get-TEPolicyTestResult -policytestname "policytestname" -nodename "nodename" -state "FAILED"
    Returns the latest result of a policy test named policytestname on a node named nodename with a state of FAILED
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
    {
        $params = @{}
        if($PolicyTestName){$params["policyTestName"] = $PolicyTestName}
        if($PolicyTestId){$params["policyTestId"] = $PolicyTestId}
        if($NodeName){$params["nodeLabel"] = $NodeName}
        if($nodeID){$params["nodeId"] = $nodeID}
        if($PolicyName){
            # Get policy test IDs under that policy
            $PolicyTests = Get-TEPolicyTest -PolicyName $PolicyName
            $PolicyTestId = $PolicyTests.id
            }
        if($State){
            if($State -in @("FAILED","PASSED","UNKNOWN","ERROR"))
                {$params["state"] = $state
                Write-Debug "State set to $state"
                }
            else
                {Write-Error "Invalid policy test result state, must be either FAILED,PASSED,UNKNOWN, or ERROR";break}
            }
        try{
            if ($PolicyTestId.count -gt 1) 
                {
                $ResultsList = @()
                Write-Information "Multiple policy test ids passed to retrieve"
                $PolicyTestId | ForEach-Object{
                    $page = 0
                    do{
                        write-debug "Getting results for policy test ID $_"
                        $params["policyTestId"] = $_
                        $PolicyTestResults = Invoke-RestMethod -Uri ($Uri+"policytestresults/latest?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
                        write-debug $PolicyTestResults
                        $page = $page + 10
                        if($policytestresults){
                            write-debug $policytestresults.nodeLabel
                            write-debug $policytestresults.policyTestName
                            write-debug $policytestresults.state
                            $ResultsList += $PolicyTestResults
                            write-debug $ResultsList.id.Count
                            }
                        }
                    while($policytestresults.count -ne 0)
                    }
                return $ResultsList
                }
            else{
                $page = 0
                do{
                    $PolicyTestResults = Invoke-RestMethod -Uri ($Uri+"policytestresults/latest?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
                    $page = $page + 10
                    $ResultsList += $PolicyTestResults
                    }
                while($policytestresults.count -ne 0)
                return $ResultsList
                }
            }
        catch
            {Write-Error "Failed to get policy test results"}
    }
}
#TODO: Update this to reflect current commandlet function designs
function Get-TEPolicyTestResultByOIDandTestStateandHours{
    param($PolicyTestOID,$NodeOID,$TestState,$Hours)
    If(!$ActivesessionVariable){Write-Host "Please login using Get-TE-REST-Login first";break}
    $validTestStates = "FAILED","PASSED","UNKNOWN"
    $creationTimeRangeStart = (Get-Date).AddHours(-$Hours)
    $creationTimeRangeStart = '{0:yyyy-MM-ddTHH:mm:s.000Z}' -f $creationTimeRangeStart
    $creationTimeRangeEnd = (Get-Date)
    $creationTimeRangeEnd = '{0:yyyy-MM-ddTHH:mm:s.000Z}' -f $creationTimeRangeEnd
    if($validTestStates.Contains($TestState)){
        $policytestresult = Invoke-RestMethod -Uri ($Uri+'policytestresults/latest?nodeId='+$NodeOID+'&policyTestId='+$PolicyTestOID+'&state='+$TestState+"&creationTimeRange=$creationTimeRangeStart,$creationTimeRangeEnd") -Method Get -ContentType 'Application/json' -Headers $headers -WebSession $ActiveSessionVariable
    }
    else{Write-host "State must be either, FAILED, PASSED or UNKNOWN"; Break}
    return $policytestresult
}
#TODO: Update this to reflect current commandlet function designs
function Get-TEPolicyResultByNodeGroupSyslogMessageFormat{
    param($PolicyName,$NodeGroupName)
    If(!$ActivesessionVariable){Write-Host "Please login using Get-TE-REST-Login first";break}
    $resultlist = @()
    try{$policyTests = Get-TEPolicyTest -PolicyName $PolicyName}catch{Write-error "Failed to find policy"}
    try{
        $nodelist = Get-TENodeGroupDescendantNodes -NodeGroupName $NodeGroupName
        try
            {
                $nodelist | ForEach-Object{
                    $CurrentNodeID = $_.id
                    $policyTests | ForEach-Object{
                        $testID = $_.id
                        $resultList += ((Get-TEPolicyTestResult -nodeID $CurrentNodeID -PolicyTestId $testID))
                    }
                }
            }
        catch  
            {
                Write-Error "Failed to find Policy Test"
            }
        }
    catch
        {
        Write-Error "Failed to find node $NodeName"
        }
        # Reformat for syslog format
    $resultList | ForEach-Object{
        $NodeName = $_.nodeLabel
        $PolicyTestName = $_.PolicyTestName
        $PolicyTestActual = $_.actual
        $PolicyTestState = $_.state
        $PolicyTestDateStamp = $_.creationTime
        $PolicyTestElement = $_.elementName
        $SyslogMessage = "CEF:0|Tripwire|Enterprise|5.5|5|Test result Change|8|dvchost=$NodeName|cs1=$policyName|cs1Label=Policy Name|cs2=$PolicyTestName|cs2Label=Test Name|cs3=$PolicyTestElement|cs3Label=Actual Result Key|cs4=$PolicyTestActual|cs4Label=Actual Result Value|cn1=$PolicyTestDateStamp|cs3=$PolicyTestState|cs3Label=Pass/Fail|dhost=mpzhwtwco01|furtherInfo=null"
        Write-host $SyslogMessage
        $SyslogResult += @($SyslogMessage)
    }
    return $SyslogResult
}
#TODO: Update this to reflect current commandlet function designs
function Get-TEPolicyResultByNodeGroupSyslogMessageFormatFiltered{
    param($PolicyName,$NodeGroupName,$TestState)
    If(!$ActivesessionVariable){Write-Host "Please login using Get-TE-REST-Login first";break}
    $resultlist = @()
    try{$policyTests = Get-TEPolicyTests -PolicyName $PolicyName}catch{Write-error "Failed to find policy"}
    try{
        $nodelist = Get-TENodeGroupDescendantNodes -NodeGroupName $NodeGroupName
        try
            {
                $nodelist | ForEach-Object{
                    $CurrentNodeID = $_.id
                    $policyTests | ForEach-Object{
                        $testID = $_.id
                        $resultList += ((Get-TEPolicyTestResult -nodeID $CurrentNodeID -PolicyTestId $testID -State $TestState))
                    }
                }
            }
        catch  
            {
                Write-Error "Failed to find Policy Test"
            }
        }
    catch
        {
        Write-Error "Failed to find node $NodeName"
        }
        # Reformat for syslog format
    $resultList | ForEach-Object{
        $NodeName = $_.nodeLabel
        $PolicyTestName = $_.PolicyTestName
        $PolicyTestState = $_.state
        $PolicyTestActual = $_.actual
        $PolicyTestDateStamp = $_.creationTime
        $PolicyTestElement = $_.elementName
        $SyslogMessage = "CEF:0|Tripwire|Enterprise|5.5|5|Test result Change|8|dvchost=$NodeName|cs1=$policyName|cs1Label=Policy Name|cs2=$PolicyTestName|cs2Label=Test Name|cs3=$PolicyTestElement|cs3Label=Actual Result Key|cs4=$PolicyTestActual|cs4Label=Actual Result Value|cn1=$PolicyTestDateStamp|cs3=$PolicyTestState|cs3Label=Pass/Fail|dhost=mpzhwtwco01|furtherInfo=null"
        Write-host $SyslogMessage
        $SyslogResult += @($SyslogMessage)
    }
    return $SyslogResult
}
#TODO: Update this to reflect current commandlet function designs
function Get-TEPolicyResultByNodeGroupSyslogMessageFormatFilteredByStateAndHours{
    param($PolicyName,$NodeGroupName,$TestState,$Hours)
    If(!$ActivesessionVariable){Write-Host "Please login using Get-TE-REST-Login first";break}
    $resultlist = @()
    try{$policyTests = Get-TEPolicyTest -PolicyName $PolicyName}catch{Write-error "Failed to find policy"}
    try{
        $nodelist = Get-TENodeGroupDescendantNodes -NodeGroupName $NodeGroupName
        try
            {
                $nodelist | ForEach-Object{
                    $CurrentNodeID = $_.id
                    $policyTests | ForEach-Object{
                        $testID = $_.id
                        $resultList += ((Get-TEPolicyTestResultByOIDandTestStateAndHours -NodeOID $CurrentNodeID -PolicyTestOID $testID -TestState $TestState -Hours $Hours))
                    }
                }
            }
        catch  
            {
                Write-Error "Failed to find Policy Test"
            }
        }
    catch
        {
        Write-Error "Failed to find node $NodeName"
        }
        # Reformat for syslog format
    $resultList | ForEach-Object{
        $NodeName = $_.nodeLabel
        $PolicyTestName = $_.PolicyTestName
        $PolicyTestState = $_.state
        $PolicyTestActual = $_.actual
        $PolicyTestDateStamp = $_.creationTime
        $PolicyTestElement = $_.elementName
        $SyslogMessage = "CEF:0|Tripwire|Enterprise|5.5|5|Test result Change|8|dvchost=$NodeName|cs1=$policyName|cs1Label=Policy Name|cs2=$PolicyTestName|cs2Label=Test Name|cs3=$PolicyTestElement|cs3Label=Actual Result Key|cs4=$PolicyTestActual|cs4Label=Actual Result Value|cn1=$PolicyTestDateStamp|cs3=$PolicyTestState|cs3Label=Pass/Fail|dhost=mpzhwtwco01|furtherInfo=null"
        Write-host $SyslogMessage
        $SyslogResult += @($SyslogMessage)
    }
    return $SyslogResult
}
function Remove-TEPolicyTest{
    param($Name,$ID)
    <#
    .SYNOPSIS
    Removes a TE policy test
    .DESCRIPTION
    Removes a TE policy based on either
    - id
    - name
    .EXAMPLE
    Remove-TEPolicyTest -Name "My Test"
    Removes a policy test called "My Test"
    .EXAMPLE
    Remove-TEPolicyTest -id "-1y2p0ij32e8at:-1y2p0ij2wozym"
    Removes a policy test  with the id -1y2p0ij32e8at:-1y2p0ij2wozym
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        if($Name){$ItemToRemove = Get-TEPolicyTest -name $Name}
        elseif($ID){$ItemToRemove = Get-TEPolicyTest -ID $ID}
        else{Write-Error "Please specify either a name or an ID"}
        if($ItemToRemove.id.count -gt 1){Write-Warning "Multiple matching tests found, using first found"}
        elseif($ItemToRemove.id.count -eq 0){Write-error "Policy not found"; break}
        $ItemToRemove = $ItemToRemove[0].id
        $remove = Invoke-RestMethod -Uri ($Uri+'policytests/'+$ItemToRemove) -Method DELETE -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
        return $remove
    }
}
# -------------------- REST API ---------------------------
# -------------------- Waivers  ---------------------------
function Get-TEWaivers{
    param($Name,$ID,$policyName,$grantedBy,$responsible,[boolean]$closed,$classification)
    <#
    .SYNOPSIS
    Gathers TE policy waivers with optional filtering
    .DESCRIPTION
    Gathers TE policy waivers with optional filtering:
    - name
    - id (object id)
    - closed (true/false)
    - grantedby
    - policyName
    - responsible
    - classification
    .EXAMPLE
    Get-TEWaivers
    Returns all policies
    .EXAMPLE
    Get-TEWaivers -policyName "My Example Policy"
    Gets any waivers for the My Example Policy policy
    .EXAMPLE
    Get-TEWaivers -closed $true
    Returns closed waivers
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus)){
        $page = 0
        $params = @{}
        if($name){$params["name"] = $name}
        if($id){$params["id"] = $id}
        if($policyName){$params["policyName"] = $policyName}
        if($grantedBy){$params["grantedBy"] = $grantedBy}
        if($responsible){$params["responsible"] = $responsible}
        if($closed){$params["closed"] = $closed}
        if($classification){$params["classification"] = $classification}
        do{    
            $waiverset = Invoke-RestMethod -Uri ($Uri+"waivers?pageLimit=10&pageStart=$page") -Method Get -body $Params -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable
            $page = $page + 10
            $waivers += $waiverset
        }while($waiverset.count -ne 0)
        return $waivers
    }
}
#TODO: Update this to reflect current commandlet function designs
function New-TEWaiver{
    param([parameter(mandatory)]$waiverDescription,[parameter(mandatory)]$waiverName,[parameter(mandatory)]$waiverGrantedBy,[parameter(mandatory)]$waiverResponsible,[parameter(mandatory)]$waiveredNodeName,[parameter(mandatory)]$waiveredPolicyTest,[parameter(mandatory)]$waiveredPolicy,$waiverExpiration,$StartTime)
    <#
    .SYNOPSIS
    Grants/creates TE policy waivers
    .DESCRIPTION
    Grants/creates TE policy waivers
    .EXAMPLE
    New-TEWaiver -policyName "My Example Policy" -waiverDescription "My waiver description" -waiverName "My waiver name" -waiverGrantedBy "My waiver granted by" -waiverResponsible "My waiver responsible" -waiveredNodeName "My waiver node name" -waiveredPolicyTest "My waiver policy test" -waiveredPolicy "My waiver policy" -waiverExpiration "2019-11-10T05:40:31.000Z"
    Adds a new waiver
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
        {
        # Start Time
        if($null -eq $starttime)
            {
            write-debug "No start time set, setting to now"
            $startTime = (Get-Date)
            $startTime = Get-Date $startTime -format "yyyy-MM-dd'T'hh:mm:ss.000'Z'"
            }
        else
            {
            try {$startTime = Get-Date $startTime -format "yyyy-MM-dd'T'hh:mm:ss.000'Z'"}catch{Write-Error "Failed to parse start time"}
            }
        # Expiration
        if($null -eq $waiverExpiration)
            {
            Write-Warning "No expiration date set, setting to 1 year from now"
            $waiverExpiration = (Get-Date).AddYears(1)
            $waiverExpiration = Get-Date $waiverExpiration -format "yyyy-MM-dd'T'hh:mm:ss.000'Z'"
            }
        else
            {
            try {$waiverExpiration = Get-Date $waiverExpiration -format "yyyy-MM-dd'T'hh:mm:ss.000'Z'"}catch{Write-Error "Failed to parse expiration date"}
            }
        # Get Policy Info
        $policy = Get-TEPolicies -Name $waiveredPolicy
        if($policy.id.count -eq 0){Write-Error "Policy not found";break}
        elseif($policy.id.count -gt 1){Write-Warning "Multiple policies found, using first only"}
        $PolicyId = $policy[0].id
        # Get Node Info
        $Node = Get-TENodes -name $waiveredNodeName
        if($Node.id.count -eq 0){Write-Error "Node not found";break}
        elseif($Node.id.count -gt 1){Write-Warning "Multiple nodes found, using first only"}
        $NodeId = $Node[0].id
        # Get Policy Test Info
        $policyTest = Get-TEPOlicyTest -Name $waiveredPolicyTest
        if($policyTest.id.count -eq 0){Write-Error "Policy test not found";break}
        elseif($policyTest.id.count -gt 1){Write-Warning "Multiple policy tests found, using first only"}
        $policyTestId =$policyTest[0].id
        $waiverNodeTest = @{"nodeId"=$nodeid;
                            "nodeGroupableId"=$nodeid;
                            "policyTestId"=$policyTestId;
                        }
        $json = @{"closed"= $false;
                "description"= "$waiverDescription";
                "expiration"= "$waiverExpiration";
                "grantedBy"= "$waiverGrantedBy";
                "name"= "$waiverName";
                "policyId"= "$policyId";
                "responsible"= "$waiverResponsible";
                "startTime"= "$startTime";
                "waivedTests"= $waiverNodeTest
        } | ConvertTo-Json
        $json = @{closed=$false; description=$waiverDescription; expiration=$waiverExpiration; grantedBy= $waiverGrantedBy; name = "$waiverName"; policyId = "$policyId"; responsible = "$waiverResponsible"; startTime= "$startTime"; waivedTests=@($waiverNodeTest)} | ConvertTo-Json
        Write-debug $json
        $waiver = Invoke-RestMethod -Uri ($Uri+'waivers') -Method POST -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $json
        return $waiver
        }
}
#TODO: Update this to reflect current commandlet function designs
 function Update-TEWaiver{
    param($waiverID,$waiverDescription,$waiverName,$waiverGrantedBy,$waiverResponsible,$waiveredNodeName,$waiveredPolicyTest,$waiveredPolicy,$waiverExpiration,[boolean]$CreateIfNotPresent)
    <#
    .SYNOPSIS
    Updates/creates TE policy waivers
    .DESCRIPTION
    Updates/creates TE policy waivers
    .EXAMPLE
    Update-TEWaiver-TEWaiver -policyName "My Example Policy" -waiverDescription "My waiver description" -waiverName "My waiver name" -waiverGrantedBy "My waiver granted by" -waiverResponsible "My waiver responsible" -waiveredNodeName "My waiver node name" -waiveredPolicyTest "My waiver policy test" -waiveredPolicy "My waiver policy" -waiverExpiration "2019-11-10T05:40:31.000Z" -CreateIfNotPresent $true
    Updates (or, if it does not already exist, creates a new waiver)
    .NOTES
    #>
    if($true -eq (Get-TEAPILoginStatus))
        {
        # Get existing waiver
        if($null -ne $waiverID){$existingWaiver = Get-TEWaivers -ID $waiverID}
        elseif ($null -ne $waiverName) {$existingWaiver = Get-TEWaivers -Name $waiverName}
        if($null -eq $existingWaiver)
            {Write-Warning "Existing waiver not found"
            if($CreateIfNotPresent -eq $true)
                {
                Write-Information "Creating new waiver"
                New-TEWaiver -waiverDescription $waiverDescription -waiverName $waiverName -waiverGrantedBy $waiverGrantedBy -waiverResponsible $waiverResponsible -waiveredNodeName $waiveredNodeName -waiveredPolicyTest $waiveredPolicyTest -waiveredPolicy $waiveredPolicy -waiverExpiration $waiverExpiration
                }
            }
            else
                {
                Write-Information "Existing waiver found"
                $waiverID = $existingWaiver.id
                Write-debug "Existing waiver id: $waiverID"
                # Get Node Info
                $Node = Get-TENodes -name $waiveredNodeName
                if($Node.id.count -eq 0){Write-Error "Node not found";break}
                elseif($Node.id.count -gt 1){Write-Warning "Multiple nodes found, using first only"}
                $NodeId = $Node[0].id
                # Get Policy Test Info
                $policyTest = Get-TEPolicyTest -Name $waiveredPolicyTest
                if($policyTest.id.count -eq 0){Write-Error "Policy test not found";break}
                elseif($policyTest.id.count -gt 1){Write-Warning "Multiple policy tests found, using first only"}
                # Create new waiver info
                $waiverNodeTest = @{"nodeId"=$nodeid;
                                    "nodeGroupableId"=$nodeid;
                                    "policyTestId"=$policyTestId;
                                }
                $json = @{"closed"= $false;
                    "description"= "$waiverDescription";
                    "expiration"= "$waiverExpiration";
                    "grantedBy"= "$waiverGrantedBy";
                    "name"= "$waiverName";
                    "responsible"= "$waiverResponsible";
                    "startTime"= "$startTime";
                    "waivedTests"= $waiverNodeTest
                } | ConvertTo-Json
                $json = @{closed=$false; description=$waiverDescription; expiration=$waiverExpiration; grantedBy= $waiverGrantedBy; name = "$waiverName"; policyId = "$policyId"; responsible = "$waiverResponsible"; startTime= "$startTime"; waivedTests=@($waiverNodeTest)} | ConvertTo-Json
                $test1 = $json | ConvertFrom-Json
                $test2 = $existingWaiver
                mergeJson -source $test2 -target $test1
                Write-host $test2
                $waiver = Invoke-RestMethod -Uri ($Uri+"waivers/$waiverId") -Method PUT -ContentType 'application/json' -Headers $headers -WebSession $ActiveSessionVariable -Body $json
                return $waiver
                }
        }
}
