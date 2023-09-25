$icingaApiHost     = "neteye.host"
$IcingaApiPort     = 5665
$icingaApiUser     = "api-user"
$icingaApiPassword = "api-password"
$DMIN = $args[0]
if ([string]::IsNullOrEmpty($DMIN)) {
	Write-Host "Usage: neteye_set_host_and_service_downtime.ps1 <DMIN> <COMMENT> [<HOSTNAME>]"
	Break
}
$DCOMMENT = $args[1]
if ([string]::IsNullOrEmpty($DCOMMENT)) {
	Write-Host "Usage: neteye_set_host_and_service_downtime.ps1 <DMIN> <COMMENT> [<HOSTNAME>]"
	Break
}
$DHOST = $args[2]
if ([string]::IsNullOrEmpty($DHOST)) {
    if ((Get-WmiObject win32_computersystem).Domain) {
        [string]$DHOST = ([string]::Format('{0}.{1}',
            (Get-WmiObject win32_computersystem).DNSHostName,
            (Get-WmiObject win32_computersystem).Domain
        )).ToLower();
    } else {
        [string]$DHOST = ((Get-WmiObject win32_computersystem).DNSHostName).ToLower();
    }
	if ([string]::IsNullOrEmpty($DHOST)) {
		Write-Host "Usage: neteye_set_host_and_service_downtime.ps1 <DMIN> <COMMENT> [<HOSTNAME>]"
		Break
	}
}

$requestUrl = "https://{0}:{1}/v1/actions/schedule-downtime" -f $icingaApiHost,$IcingaApiPort


# Put the certificate from your master (/etc/icinga2/pki/*.crt) here.
# You will get it with "openssl s_client -connect <master>:5665" too.

$Cert64=@"
    -----BEGIN CERTIFICATE-----
    1 Paste NetEye Root CA crt here indented
    2
    3
    .
	.
	.
    n
    -----END CERTIFICATE-----
"@

# register callback for comparing the certificate
function set-SSLCertificate {
    param(
        $Cert
    )

    if (-not("validateCert" -as [type])) {
        add-type -TypeDefinition @"
            using System.Net.Security;
            using System.Security.Cryptography.X509Certificates;

            public static class ValidateCert {
                static X509Certificate2 MyCert;

                public static bool Validate(object sender,
                    X509Certificate cert,
                    X509Chain chain,
                    SslPolicyErrors sslPolicyErrors) {
                        if (MyCert.Equals(cert)) {
                            return true;
                        } else {
                            return false;
                        }
                }

                public static RemoteCertificateValidationCallback GetDelegate(X509Certificate2 Cert) {
                    MyCert = Cert;
                    return new RemoteCertificateValidationCallback(ValidateCert.Validate);
                }
            }
"@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [validateCert]::GetDelegate($Cert)
}

# convert base64 based certificate to X509 certificate
function get-x509 {
    param(
        [string]
            $Cert64
    )

    $CertBin=[System.Convert]::FromBase64String(($Cert64.Trim(" ") -replace "-.*-",""))

    #Write-Host ($Cert64.Trim(" ") -replace "-.*-","")

    [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertBin
}

# Allow TLS 1.2. Old powershell (.net) uses TLS 1.0 only. Icinga2 >2.10 needs TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'

$SecPass = ConvertTo-SecureString $icingaApiPassword -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($icingaApiUser, $SecPass)

$Cert = get-x509 $Cert64
set-SSLCertificate $Cert

$httpHeaders = @{
    "accept"                 = "application/json"
}

# Start and End time in epoch
$start_time = [int][double]::Parse((Get-Date (Get-Date).ToUniversalTime() -UFormat %s))
$end_time = [int][double]::Parse((Get-Date ((Get-Date).AddMinutes($DMIN)).ToUniversalTime() -UFormat %s))
$data = @{
    "pretty"       = 1
    "filter"       = 'match("'+$DHOST+'", host.name)'
    "type"         = 'Host'
	"all_services" = 1
	"author"       = 'windows-cli'
	"comment"      = $DCOMMENT
	"fixed"        = 1
	"start_time"   = $start_time
	"end_time"     = $end_time
}

$JSON = (ConvertTo-Json -InputObject $data)
$JSON

$result = Invoke-RestMethod -Uri $requestUrl -Method "POST" -Body (ConvertTo-Json -InputObject $data)  -Credential $Cred -ContentType "application/json" -Headers $httpHeaders

$result