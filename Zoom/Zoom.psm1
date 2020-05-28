$script:TokenCache = @{
    Key       = $null
    Secret    = $null
    Header    = $null
    Timeout   = 360
    ExpiresOn = $null
}


function New-ZoomJwt {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateSet("HS256", "HS384", "HS512")]
        $Algorithm = $null,

        $Type = $null,

        [Parameter(Mandatory = $True)]
        [string]$Issuer = $null,

        [int]$ValidforSeconds = $null,

        [Parameter(Mandatory = $True)]
        $SecretKey = $null
    )

    # Grab Unix Epoch Timestamp and add desired expiration
    $exp = [int][double]::Parse((Get-Date -Date $((Get-Date).AddSeconds($ValidforSeconds).ToUniversalTime()) -UFormat %s))

    [hashtable]$header = @{
        alg = $Algorithm
        typ = $Type
    }
    [hashtable]$payload = @{
        iss = $Issuer
        exp = $exp
    }

    $headerjson = $header | ConvertTo-Json -Compress
    $payloadjson = $payload | ConvertTo-Json -Compress
    $headerjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
    $payloadjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')

    $toBeSigned = $headerjsonbase64 + "." + $payloadjsonbase64

    $signingAlgorithm = switch ($Algorithm) {
        "HS256" {
            New-Object System.Security.Cryptography.HMACSHA256
        }
        "HS384" {
            New-Object System.Security.Cryptography.HMACSHA384
        }
        "HS512" {
            New-Object System.Security.Cryptography.HMACSHA512
        }
    }

    $signingAlgorithm.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $signature = [Convert]::ToBase64String($signingAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($toBeSigned))).Split('=')[0].Replace('+', '-').Replace('/', '_')

    $token = "$headerjsonbase64.$payloadjsonbase64.$signature"
    return $token
}


function Set-ZoomApiAuth {
    <#
    .SYNOPSIS
    Sets the TokenCache Key and Secret and sets/returns a header with a new token.

    .EXAMPLE
    $Header = Get-ZoomApiAuth

    .OUTPUTS
    Hashtable
    #>
    [CmdletBinding()]
    param(
        [string]$Key,
        [string]$Secret
    )
    try {
        if ($null -eq $script:TokenCache.Key) {
            if ($Key -and $Secret) {
                $script:TokenCache.Key = $Key
                $script:TokenCache.Secret = $Secret
            } else {
                $script:TokenCache.Key = Get-AutomationVariable -Name ZoomApiKey
                $script:TokenCache.Secret = Get-AutomationVariable -Name ZoomApiSecret
            }
        }
    } catch {
        $_
    }

    $token = New-ZoomJwt -Algorithm 'HS256' -type 'JWT' -Issuer $script:TokenCache.Key -SecretKey $script:TokenCache.Secret -ValidforSeconds $script:TokenCache.Timeout
    $script:TokenCache.ExpiresOn = (Get-Date).AddSeconds($script:TokenCache.Timeout)

    $script:TokenCache.Header = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $token"
    }

    Start-Sleep -Milliseconds 500
}

function Invoke-ZoomMethod {
    <#
    .SYNOPSIS
    Wraps Zoom Api calls to support retry.

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Get', 'Put', 'Patch', 'Post', 'Delete')]
        [string]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [string]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ContentType,

        [Parameter(Mandatory = $false)]
        [int]$RetryTimeoutMilliseconds = 500,

        [Parameter(Mandatory = $false)]
        [int]$RetryCount = 3
    )

    Write-Debug "[BEGIN] Invoke-ZoomMethod - $((Get-PSCallStack)[1].Command)"

    $timeout = (Get-Date).AddSeconds(-5) -gt $script:TokenCache.ExpiresOn
    if (-not $script:TokenCache.Header -or $timeout) {
        if ($timeout) {
            Write-Debug "[AUTH_STATUS] Token Timeout"
        }
        Write-Debug "[AUTH_STATUS] Setting ZoomApiAuth..."
        Set-ZoomApiAuth
    }

    $header = $script:TokenCache.Header

    $callParams = @{
        Headers = $header
        Uri     = $Uri
        Method  = $Method
        Verbose = $false
    }

    if ($Method -ne 'Get') {
        $callParams.Add('Body', $Body)

        if ($ContentType) {
            $callParams.Add('ContentType', $ContentType)
        }
    }

    $apiCallInfo = "Method $Method | Uri $Uri"
    if ($Body) {
        $apiCallInfo += "`n$Body"
    }


    if ($Method -eq 'Get' -or $pscmdlet.ShouldProcess($apiCallInfo, 'Invoke Zoom method')) {

        Write-Debug "[INVOKE] $apiCallInfo"

        try {
            $response = Invoke-RestMethod @callParams
        } catch {
            throw $_
        }

        $retry = 0

        while ($response.PSObject.Properties.Name -match 'error' -and ($retry -lt $RetryCount)) {

            Write-Error -Message "$($response.error.message)`n$apiCallInfo" -ErrorId $response.error.code -Category InvalidOperation

            switch ($response.error.code) {
                429 {
                    Write-Warning "Throttled, retrying in $RetryTimeoutMilliseconds milliseconds..."
                    Start-Sleep -Milliseconds $RetryTimeoutMilliseconds
                }
                401 {
                    Write-Warning "Unauthorized, retrying..."
                    Set-ZoomApiAuth
                    $apiCallInfo.Header = $script:TokenCache.Header
                }
            }

            $apiCallInfo = "Method $Method | Uri $Uri"
            if ($Body) {
                $apiCallInfo += "`n$Body"
            }

            Write-Debug "[INVOKE] REST Method`n$apiCallInfo"
            $response = Invoke-RestMethod @callParams

            $retry++
        }
    }

    Write-Debug "[EXIT] Invoke-ZoomMethod - $((Get-PSCallStack)[1].Command)"

    return $response
}



#
#
#   User
#
#

function Get-ZoomUser {
    <#
    .SYNOPSIS
    Gets Zoom users by Id, Email, or All.

    .PARAMETER UserId
    Gets Zoom user by their Zoom Id or Email. Will accept an array of Id's and Emails.

    .PARAMETER LoginType
    Optional, default is Sso. Login type of the user.

    .PARAMETER All
    Default. Return all Zoom users.

    .PARAMETER Status
    Optional. Return users with a specific status.

    .EXAMPLE
    Get-ZoomUser
    Returns all zoom users.

    .EXAMPLE
    Get-ZoomUser -Email user@company.com
    Searches for and returns specified user if found.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'List'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'User'
        )]
        [Alias("Id", "Email")]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Facebook', 'Google', 'Api', 'Zoom', 'Sso')]
        [string]$LoginType,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'List'
        )]
        [switch]$List,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'All'
        )]
        [switch]$All,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'All'
        )]
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'List'
        )]
        [ValidateSet('active', 'inactive', 'pending', IgnoreCase = $false)]
        [String]$Status = 'active'
    )

    if (@('All', 'List') -contains $PSCmdlet.ParameterSetName) {
        $endpoint = 'https://api.zoom.us/v2/users?'

        $endpoint += "status=$($Status)"

        $pageSize = 300
        $endpoint += "&page_size=$($pageSize)"

        $result = Invoke-ZoomMethod -Uri $endpoint

        $users = $result.users

        if ($result.page_count -gt 1) {
            Write-Verbose "There are $($result.page_count) pages of users"
            for ($page = 2; $page -le $result.page_count; $page++) {
                $pagedEndpoint = "$endpoint&page_number=$page"

                $pageResult = Invoke-ZoomMethod -Uri $pagedEndpoint

                $users += $pageResult.users
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'List') {
            return $users
        }

        elseif ($PSCmdlet.ParameterSetName -eq 'All') {
            Write-Verbose "Retrieving all Zoom user data..."

            foreach ($user in $users) {
                try {
                    Get-ZoomUser -UserId $user.email
                } catch {
                    $user
                }
            }

            Write-Verbose "Finished retrieving Zoom user info"
        }
    } else {

        $type = switch ($LoginType) {
            'Facebook' {
                '0'
            }
            'Google' {
                '1'
            }
            'Api' {
                '99'
            }
            'Zoom' {
                '100'
            }
            'Sso' {
                '101'
            }
        }

        foreach ($user in $UserId) {
            $endpoint = "https://api.zoom.us/v2/users/$($user)"

            if ($PSBoundParameters.ContainsKey('License')) {
                $endpoint += "?login_type=$($type)"
            }

            Invoke-ZoomMethod -Uri $endpoint
        }
    }
}

function Set-ZoomUser {
    <#
    .SYNOPSIS
    Update user info on Zoom via user ID.

    .PARAMETER Id
    Zoom user to update.

    .PARAMETER FirstName
    User's first name.

    .PARAMETER LastName
    User's last name.

    .PARAMETER License
    License type. Basic, Pro, or Corp.

    .PARAMETER Pmi
    Personal Meeting ID, long, length must be 10.

    .PARAMETER EnablePmi
    Specify whether to use Personal Meeting Id for instant meetings. True or False.

    .PARAMETER VanityName
    Personal meeting room name.

    .PARAMETER EnterExitChime
    Enable enter/exit chime.

    .PARAMETER EnterExitChimeType
    Enter/exit chime type. All (0) means heard by all including host and attendees, HostOnly (1) means heard by host only.

    .PARAMETER DisableFeedback
    Disable feedback.

    .PARAMETER TimeZone
    The time zone id for user profile. For a list of id's refer to https://zoom.github.io/api/#timezones.

    .PARAMETER Department
    Department for user profile, use for reporting.

    .PARAMETER Status
    Enable or disable a Zoom user.

    .EXAMPLE
    Get-ZoomUser -Id user@company.com | Set-ZoomUser -License Corp
    Sets Zoom license to Corp on user@company.com's account.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'NoPicture'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("Email", "Id")]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserId,

        [Parameter(Mandatory = $false)]
        [string]$FirstName,

        [Parameter(Mandatory = $false)]
        [string]$LastName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Basic', 'Pro', 'Corp')]
        [string]$License,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^([0-9]{10})$')]
        [string]$Pmi,

        [Parameter(Mandatory = $false)]
        [string]$Timezone,

        [Parameter(Mandatory = $false)]
        [string]$Department,

        [Parameter(Mandatory = $false)]
        [string]$VanityName,

        [Parameter(Mandatory = $false)]
        [string]$HostKey,

        [Parameter(Mandatory = $false)]
        [ValidateSet('activate', 'deactivate', IgnoreCase = $false)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [ValidateSet('host', 'all', 'none', IgnoreCase = $false)]
        [string]$EntryExitChime,

        [Parameter(Mandatory = $false)]
        [ValidateSet('host', 'all', 'none', IgnoreCase = $false)]
        [string]$Feedback,

        #
        # Picture
        #

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Path'
        )]
        [ValidateScript( { Test-Path $_ -PathType Leaf })]
        [ValidatePattern('.jp*.g$')]
        [string]$PicturePath,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'ByteArray'
        )]
        [ValidateNotNullOrEmpty()]
        [byte[]]$PictureByteArray,

        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Binary'
        )]
        [ValidateNotNullOrEmpty()]
        $PictureBinary
    )

    process {

        $endpoint = "https://api.zoom.us/v2/users/$UserId"

        foreach ($user in $UserId) {

            $body = @{ }

            if ($PSBoundParameters.ContainsKey('FirstName')) {
                $body.Add('first_name', $FirstName)
            }
            if ($PSBoundParameters.ContainsKey('LastName')) {
                $body.Add('last_name', $LastName)
            }
            if ($PSBoundParameters.ContainsKey('License')) {
                $licenseType = switch ($License) {
                    'Basic' {
                        1
                    }
                    'Pro' {
                        2
                    }
                    'Corp' {
                        3
                    }
                }

                $body.Add('type', $licenseType)
            }
            if ($PSBoundParameters.ContainsKey('Pmi')) {
                $body.Add('pmi', $Pmi)
            }
            if ($PSBoundParameters.ContainsKey('Timezone')) {
                $body.Add('timezone', $Timezone)
            }
            if ($PSBoundParameters.ContainsKey('Department')) {
                $body.Add('dept', $Department)
            }
            if ($PSBoundParameters.ContainsKey('VanityName')) {
                $body.Add('vanity_name', $VanityName.ToLower())
            }
            if ($body.Count -gt 0) {
                Write-Verbose "Update user $user"
                $body = $body | ConvertTo-Json
                Invoke-ZoomMethod -Uri $endpoint -Body $body -Method Patch
            }


            #
            # Process Settings
            #

            $body = @{
                'in_meeting' = @{ }
            }

            if ($PSBoundParameters.ContainsKey('EntryExitChime')) {
                $body['in_meeting'].Add('entry_exit_chime', $EntryExitChime)
            }
            if ($PSBoundParameters.ContainsKey('Feedback')) {
                $body['in_meeting'].Add('feedback', $Feedback)
            }

            if ($body['in_meeting'].Count -gt 0) {
                Write-Verbose "Update settings for user $user"
                $body = $body | ConvertTo-Json
                Invoke-ZoomMethod -Uri "$endpoint/settings" -Body $body -Method Patch
            }

            #
            # Process Status
            #

            if ($PSBoundParameters.ContainsKey('Status')) {
                Write-Verbose "Update status for user $user"
                $body = @{
                    'action' = $Status
                } | ConvertTo-Json
                Invoke-ZoomMethod -Uri "$endpoint/status" -Body $body -Method Put
            }

            #
            # Process Picture
            #

            if ($pscmdlet.ParameterSetName -ne 'NoPicture') {
                if ($PSBoundParameters.ContainsKey('PicturePath')) {
                    $fileName = $PicturePath.Split('\')[-1]
                    $PictureByteArray = Get-Content -Path $PicturePath -Encoding Byte
                } else {
                    $fileName = 'ProfilePicture.jpg'
                }

                if (-not $PictureBinary) {
                    $encoding = [System.Text.Encoding]::GetEncoding('iso-8859-1')
                    $encodedFile = $encoding.GetString($PictureByteArray)
                } else {
                    $encodedFile = $PictureBinary
                }

                $newLine = "`r`n"
                $boundary = [guid]::NewGuid()

                $requestBody = (

                    "--$boundary",
                    "Content-Type: application/octet-stream",
                    "Content-Disposition: form-data; name=pic_file; filename=$fileName; filename*=utf-8''$fileName$newLine",
                    $encodedFile,
                    "--$boundary--$newLine"
                ) -join $newLine

                Write-Verbose "Update Zoom user picture for $UserId"
                Invoke-ZoomMethod -Uri "$endpoint/picture" -Body $requestBody -Method Post -ContentType "multipart/form-data; boundary=`"$boundary`""
            }
        }
    }
}

function New-ZoomUser {
    <#
    .SYNOPSIS
    Create new Zoom user account.

    .PARAMETER Email
    User's Email.

    .PARAMETER FirstName
    User's first name.

    .PARAMETER LastName
    User's last name.

    .PARAMETER License
    License type. Basic, Pro, or Corp.

    .EXAMPLE
    New-ZoomUser -Email user@company.com -License Pro
    Creates a Zoom user account for email user@company.com with a Pro license.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$Email,

        [Parameter(Mandatory = $false)]
        [ValidateSet('create', 'ssoCreate', 'autoCreate', 'custCreate', IgnoreCase = $false)]
        [string]$Action = 'ssoCreate',

        [Parameter(Mandatory = $true)]
        [ValidateSet('Basic', 'Pro', 'Corp')]
        [string]$License,

        [Parameter(Mandatory = $false)]
        [string]$FirstName,

        [Parameter(Mandatory = $false)]
        [string]$LastName

    )

    $endpoint = 'https://api.zoom.us/v2/users'

    $licenseType = switch ($License) {
        'Basic' {
            1
        }
        'Pro' {
            2
        }
        'Corp' {
            3
        }
    }

    foreach ($user in $Email) {
        $body = @{
            'action'    = $Action
            'user_info' = @{
                'email' = $user
                'type'  = $licenseType
            }
        }
        if ($PSBoundParameters.ContainsKey('FirstName')) {
            $body['user_info'].Add('first_name', $FirstName)
        }
        if ($PSBoundParameters.ContainsKey('LastName')) {
            $body['user_info'].Add('last_name', $LastName)
        }

        $body = $body | ConvertTo-Json

        Write-Verbose "Creating new Zoom user $user"
        Invoke-ZoomMethod -Uri $endpoint -Body $body -Method Post
    }
}

function Remove-ZoomUser {
    <#
    .SYNOPSIS
    Remove Zoom user by Id or Email.

    .PARAMETER UserId
    Zoom user Id or email to remove. Accepts arrays.

    .PARAMETER Permanently
    Default is false. If false user is disassociated, if true the user is permanently deleted.

    .PARAMETER TransferEmail
    If specified, the user's data will be transferred to this email account.

    .PARAMETER TransferMeeting
    Default is true. Transfers the user's meetings to the TransferEmail.

    .PARAMETER TransferWebinar
    Default is false. Transfers the user's webinars to the TransferEmail.

    .PARAMETER TransferRecording
    Default is true. Transfers the user's recordings to the TransferEmail.

    .EXAMPLE
    Get-ZoomUser -UserId user@company.com | Remove-ZoomUser -Permanently
    Permanently remove user@company.com.

    .EXAMPLE
    Remove-ZoomUser -UserId 123asdfjkl
    Removes Zoom user with Id 123asdfjkl.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("Id", "Email")]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserId,

        [switch]$Permanently,

        [string]$TransferEmail,

        [bool]$TransferMeeting = $true,

        [bool]$TransferWebinar = $false,

        [bool]$TransferRecording = $true
    )

    foreach ($user in $UserId) {
        $endpoint = "https://api.zoom.us/v2/users/$user"

        if ($Permanently) {
            Write-Verbose 'Permanent delete selected.'
            $endpoint += '?action=delete'
        } else {
            $endpoint += '?action=disassociate'
        }

        if ($TransferEmail) {
            $endpoint += "&transfer_email=$TransferEmail"
            $endpoint += "&transfer_webinar=$TransferWebinar"
            $endpoint += "&transfer_recording=$TransferRecording"
        }

        Write-Verbose "Remove Zoom user $user"
        Invoke-ZoomMethod -Uri $endpoint -Method Delete
    }
}


#
#
#   Group
#
#


function Remove-ZoomGroup {
    <#
    .SYNOPSIS
    Remove Zoom group by Id.

    .PARAMETER Id
    Zoom group Id to remove. Arrays accepted.

    .EXAMPLE
    Get-ZoomGroup -Name TestGroup | Remove-ZoomGroup
    Remove group TestGroup.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$Id
    )

    process {
        foreach ($group in $Id) {
            $endpoint = "https://api.zoom.us/v2/groups/$($group)"

            if ($pscmdlet.ShouldProcess($group, 'Remove Zoom group')) {
                Invoke-ZoomMethod -Uri $endpoint -Method Delete
            }
        }
    }
}

function Get-ZoomGroup {
    <#
    .SYNOPSIS
    Gets Zoom groups by Id, Name, or All.

    .PARAMETER Id
    Gets Zoom group by their Zoom Id.

    .PARAMETER Name
    Gets all Zoom groups and then filters by name.

    .PARAMETER All
    Default. Return all Zoom groups.

    .EXAMPLE
    Get-ZoomGroup
    Returns all zoom groups.

    .EXAMPLE
    Get-ZoomGroup -Name TestGroup
    Searches for and returns specified group if found.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'All'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Id'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Id,

        [Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All
    )

    $endpoint = 'https://api.zoom.us/v2/groups'

    if ($PSCmdlet.ParameterSetName -eq 'Id') {
        $endpoint += "/$($Id)"
        Invoke-ZoomMethod -Uri $endpoint
    } else {
        $groups = Invoke-ZoomMethod -Uri $endpoint

        if ($groups) {

            if ($PSCmdlet.ParameterSetName -eq 'Name') {
                $groups.groups | Where-Object name -eq $Name
            } else {
                $groups.groups
            }
        }
    }
}

function New-ZoomGroup {
    <#
    .SYNOPSIS
    Create a group on Zoom, return the new group info.

    .PARAMETER Name
    Group name, must be unique in one account. Arrays accepted.

    .EXAMPLE
    New-ZoomGroup -Name TestGroup
    Create new group named TestGroup.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name
    )

    begin {
        $endpoint = 'https://api.zoom.us/v2/groups'
    }

    process {
        foreach ($group in $Name) {
            $requestBody = @{
                name = $group
            } | ConvertTo-Json

            Write-Verbose "Creating new Zoom group $group"
            Invoke-ZoomMethod -Uri $endpoint -Body $requestBody -Method Post
        }
    }
}

function Add-ZoomGroupMember {
    <#
    .SYNOPSIS
    Adds members to a group on Zoom.

    .PARAMETER GroupId
    Group ID.

    .PARAMETER Id
    The member IDs, pipeline and arrays are accepted

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$Id,

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$Email
    )

    begin {
        $endpoint = "https://api.zoom.us/v2/groups/$($GroupId)/members"

        $users = @()
    }

    process {
        foreach ($user in $Id) {
            $users += @{ 'id' = $user }
        }

        foreach ($user in $Email) {
            $users += @{ 'email' = $user }
        }
    }

    end {
        # API allows 30 users per call to be added
        for ($i = 0; $i -lt $users.Count; $i += 30) {
            $userBatch = $users[$i..($i + 29)]

            $requestBody = @{
                'members' = $userBatch
            } | ConvertTo-Json

            Write-Verbose "Add Zoom user(s) to $GroupId`: $($userBatch.id -join ',')"
            Invoke-ZoomMethod -Uri $endpoint -Body $requestBody -Method Post
        }
    }
}

function Remove-ZoomGroupMember {
    <#
    .SYNOPSIS
    Remove members to a group on Zoom.

    .PARAMETER GroupId
    Group ID.

    .PARAMETER Id
    The member IDs, pipeline and arrays are accepted

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupId,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$Id
    )

    process {
        foreach ($user in $Id) {
            $endpoint = "https://api.zoom.us/v2/groups/$($GroupId)/members/$($user)"

            Write-Verbose "Remove Zoom user(s) from $GroupId`: $($user -join ',')"
            Invoke-ZoomMethod -Uri $endpoint -Method Delete
        }
    }
}

function Get-ZoomGroupMember {
    <#
    .SYNOPSIS
    Lists the members of a group on Zoom.

    .PARAMETER Id
    Group ID.

    .EXAMPLE
    Get-ZoomGroup -Name TestGroup | Get-ZoomGroupMember
    Gets members of TestGroup.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )

    $endpoint = "https://api.zoom.us/v2/groups/$($Id)/members?"
    $pageSize = 300

    $endpoint += "page_size=$($pageSize)"

    $result = Invoke-ZoomMethod -Uri $endpoint

    $users = $result.members

    if ($result.page_count -gt 1) {
        Write-Verbose "There are $($result.page_count) pages of users"
        for ($page = 2; $page -le $result.page_count; $page++) {
            $pagedEndpoint = "$endpoint&page_number=$page"

            $pageResult += Invoke-ZoomMethod -Uri $pagedEndpoint

            $users += $pageResult.members
        }
    }

    return $users
}



#
#
#    Tests
#
#


function Test-ZoomUserEmail {
    <#
    .SYNOPSIS
    Test if given email has an existing account.

    .PARAMETER Email
    Zoom user email to test. Arrays accepted.

    .EXAMPLE
    Test-ZoomUserEmail -Email user@company.com
    Checks to see if account exists for user@company.com.

    .NOTES
    This will return false if the user has an SSO account but not an Email account.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$Email
    )

    process {
        foreach ($user in $Email) {
            $endpoint = "https://api.zoom.us/v2/users/email?email=$($user)"

            Invoke-ZoomMethod -Uri $endpoint | Select-Object -ExpandProperty existed_email
        }
    }
}

function Test-ZoomMeetingVanityName {
    <#
    .SYNOPSIS
    Test if given vanity name exists.

    .PARAMETER VanityName
    Zoom user meeting vanity name. Arrays accepted.

    .EXAMPLE
    Test-ZoomMeetingVanityName -VanityName joe.brown
    Checks to see if vanity meeting room name exists.

    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string[]]$VanityName
    )

    process {
        foreach ($name in $VanityName) {
            $endpoint = "https://api.zoom.us/v2/users/vanity_name?vanity_name=$($name)"

            Write-Verbose "Test for existing vanity name $name"
            Invoke-ZoomMethod -Uri $endpoint | Select-Object -ExpandProperty existed
        }
    }
}

function Get-ZoomUserMeeting {
    <#
    .SYNOPSIS
    Gets all meetings for a Zoom user.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("Id", "Email")]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('scheduled', 'live', 'upcoming', IgnoreCase = $false)]
        [String]$Type = 'live'
    )

    process {
        foreach ($user in $UserId) {
            $endpoint = "https://api.zoom.us/v2/users/$($user)/meetings?"

            $endpoint += "type=$($Type)"

            $pageSize = 300
            $endpoint += "&page_size=$($pageSize)"

            Write-Verbose "Getting $Type Zoom meetings for $user"
            $result = Invoke-ZoomMethod -Uri $endpoint

            $meetings = $result.meetings

            if ($result.page_count -gt 1) {
                Write-Verbose "There are $($result.page_count) pages of meetings"
                for ($page = 2; $page -le $result.page_count; $page++) {
                    $pagedEndpoint = "$endpoint&page_number=$page"

                    $pageResult = Invoke-ZoomMethod -Uri $pagedEndpoint

                    $meetings += $pageResult.meetings
                }
            }

            return $meetings
        }
    }
}

function Get-ZoomMeeting {
    <#
    .SYNOPSIS
    Gets Zoom meeting info.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [int64[]]$Id
    )

    begin {
        $endpoint = 'https://api.zoom.us/v2/meetings'
    }

    process {
        foreach ($meeting in $Id) {
            Write-Verbose "Get Zoom meeting info for $meeting"
            Invoke-ZoomMethod -Uri "$endpoint/$meeting"
        }
    }
}

function Clear-ZoomUserPmi {
    <#
    .SYNOPSIS
    Update user Zoom user PMI (Private Meeting ID) to a random number starting with "555".

    .PARAMETER Id
    Zoom user to update.

    .EXAMPLE
    Get-ZoomUser -Id user@company.com | Clear-ZoomUserPmi
    Sets Zoom user PMI to a random number on user@company.com's account.

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("Email", "Id")]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserId
    )

    process {
        foreach ($user in $UserId) {
            $endpoint = "https://api.zoom.us/v2/users/$UserId"

            if ($pscmdlet.ShouldProcess($user, 'Clear Zoom user PMI')) {
                do {
                    $randomPmi = "555$(Get-Random -Minimum 1000000 -Maximum 10000000)"
                    Write-Verbose "Random PMI: $randomPmi"

                    $body = @{ pmi = $randomPmi } | ConvertTo-Json

                    try {
                        Invoke-ZoomMethod -Uri $endpoint -Body $body -Method Patch
                        $code = 0
                    } catch {
                        $code = ($_.ErrorDetails.Message | ConvertFrom-Json).code
                    }
                    # return code 3016 means the PMI is already in use, so try again
                } while ($code -eq 3016)
            }
        }
    }
}

function Get-ZoomPhoneUser {
    <#
    .SYNOPSIS
    Gets Zoom phone users by Id, Email, or All.

    .PARAMETER UserId
    Gets Zoom phone user by their Zoom Id or Email. Will accept an array of Id's and Emails.

    .PARAMETER List
    Return all Zoom phone users with limited properties.

    .PARAMETER All
    Default. Return all Zoom phone users.

    .EXAMPLE
    Get-ZoomPhoneUser
    Returns all zoom phone users.

    .EXAMPLE
    Get-ZoomPhoneUser -Email user@company.com
    Searches for and returns specified phone user if found.

    .NOTES
    https://marketplace.zoom.us/docs/api-reference/zoom-api/phone/listphoneusers
    https://marketplace.zoom.us/docs/api-reference/zoom-api/phone/phoneuser

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'All'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'User'
        )]
        [Alias("Id", "Email")]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserId,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'List'
        )]
        [switch]$List,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'All'
        )]
        [switch]$All
    )

    if (@('All', 'List') -contains $PSCmdlet.ParameterSetName) {
        $endpoint = 'https://api.zoom.us/v2/phone/users?'

        $pageSize = 300
        $endpoint += "&page_size=$($pageSize)"

        $result = Invoke-ZoomMethod -Uri $endpoint

        $users = $result.users

        if ($result.page_count -gt 1) {
            Write-Verbose "There are $($result.page_count) pages of phone users"
            for ($page = 2; $page -le $result.page_count; $page++) {
                $pagedEndpoint = "$endpoint&page_number=$page"

                $pageResult = Invoke-ZoomMethod -Uri $pagedEndpoint

                $users += $pageResult.users
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'List') {
            return $users
        } elseif ($PSCmdlet.ParameterSetName -eq 'All') {
            Write-Verbose "Retrieving all Zoom phone user data..."

            foreach ($user in $users) {
                try {
                    Get-ZoomPhoneUser -UserId $user.email
                } catch {
                    $user
                }
            }

            Write-Verbose "Finished retrieving Zoom phone user info"
        }
    } else {
        foreach ($user in $UserId) {
            $endpoint = "https://api.zoom.us/v2/phone/users/$($user)"

            try {
                Invoke-ZoomMethod -Uri $endpoint
            } catch [System.Net.WebException] {
                if ($_.Exception.Response.StatusCode -eq 'NotFound') {
                    Write-Warning "Phone user $user does not exist."
                } else {
                    Write-Warning "Web Exception: $($_.Exception.Message)"
                }
            } catch {
                $_
            }
        }
    }
}

function Get-ZoomPhoneNumber {
    <#
    .SYNOPSIS
    Gets Zoom phone numbers by Id or All.

    .PARAMETER Id
    Gets Zoom numbers by their Zoom Id. Will accept an array of Id's.

    .PARAMETER List
    Gets all Zoom numbers with limited properties.

    .PARAMETER All
    Default. Return all Zoom phone numbers with full properties.

    .PARAMETER Type
    Query response by number assignment. The value can be one of the following:
    assigned: The number has been assigned to either a user.
    unassigned: The number is not assigned to anyone.
    all: Include both assigned and unassigned numbers in the response.

    .PARAMETER ExtensionType
    The type of assignee to whom the number is assigned. The value can be one of the following: user, callQueue, autoReceptionist, commonAreaPhone.

    .PARAMETER NumberType
    The type of phone number. The value can be either toll or tollfree.

    .PARAMETER PendingNumbers
    Include or exclude pending numbers in the response. The value can be either $true or $false.

    .EXAMPLE
    Get-ZoomPhoneNumber
    Returns all zoom phone numbers.

    .EXAMPLE
    Get-ZoomPhoneNumber -Id asdfasdf12341234
    Searches for and returns specified phone number by Id if found.

    .NOTES
    https://marketplace.zoom.us/docs/api-reference/zoom-api/phone/listaccountphonenumbers
    https://marketplace.zoom.us/docs/api-reference/zoom-api/phone/getphonenumberdetails

    .OUTPUTS
    PSCustomObject
    #>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'All'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Number'
        )]
        [Alias("Number")]
        [ValidateNotNullOrEmpty()]
        [string[]]$Id,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'List')]
        [switch]$List,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'All')]
        [switch]$All,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'List')]
        [Parameter(ParameterSetName = 'All')]
        [ValidateSet('assigned', 'unassigned', 'all')]
        [Alias("AssignmentType")]
        [string]$Type = 'all',

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'List')]
        [Parameter(ParameterSetName = 'All')]
        [ValidateSet('user', 'callQueue', 'autoReceptionist', 'commonAreaPhone')]
        [string]$ExtensionType,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'List')]
        [Parameter(ParameterSetName = 'All')]
        [ValidateSet('toll', 'tollfree')]
        [string]$NumberType,

        [Parameter(Mandatory = $false)]
        [Parameter(ParameterSetName = 'List')]
        [Parameter(ParameterSetName = 'All')]
        [bool]$PendingNumbers = $false
    )

    if ($PSCmdlet.ParameterSetName -ne "Number") {
        $endpoint = 'https://api.zoom.us/v2/phone/numbers?'

        $pageSize = 300
        $endpoint += "&page_size=$($pageSize)"

        if ($PSBoundParameters.ContainsKey('Type')) {
            $endpoint += "&type=$($Type)"
        }
        if ($PSBoundParameters.ContainsKey('ExtensionType')) {
            $endpoint += "&extension_type=$($ExtensionType)"
        }
        if ($PSBoundParameters.ContainsKey('NumberType')) {
            $endpoint += "&number_type=$($NumberType)"
        }
        if ($PSBoundParameters.ContainsKey('PendingNumbers')) {
            $endpoint += "&pending_numbers=$($PendingNumbers)"
        }

        $result = Invoke-ZoomMethod -Uri $endpoint

        $numbers = $result.phone_numbers

        if ($result.page_count -gt 1) {
            Write-Verbose "There are $($result.page_count) pages of phone numbers"
            for ($page = 2; $page -le $result.page_count; $page++) {
                $pagedEndpoint = "$endpoint&page_number=$page"

                $pageResult = Invoke-ZoomMethod -Uri $pagedEndpoint

                $numbers += $pageResult.phone_numbers
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'List') {
            return $numbers
        } elseif ($PSCmdlet.ParameterSetName -eq 'All') {
            Write-Verbose "Retrieving all Zoom phone numbers data..."

            foreach ($number in $numbers) {
                try {
                    Get-ZoomPhoneNumber -Id $number.id
                } catch {
                    $number
                }
            }

            Write-Verbose "Finished retrieving Zoom phone number info"
        }
    } else {
        foreach ($number in $Id) {
            $endpoint = "https://api.zoom.us/v2/phone/numbers/$($number)"

            try {
                Invoke-ZoomMethod -Uri $endpoint
            } catch [System.Net.WebException] {
                if ($_.Exception.Response.StatusCode -eq 'NotFound') {
                    Write-Warning "Phone number $number does not exist."
                } else {
                    Write-Warning "Web Exception: $($_.Exception.Message)"
                }
            } catch {
                $_
            }
        }
    }
}

Export-ModuleMember -Function *