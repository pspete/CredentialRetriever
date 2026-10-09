Function Skip-CertificateCheck {
	<#
	.SYNOPSIS
	Bypass SSL Validation

	.DESCRIPTION
	Sets a certificate policy which skips ssl certificate validation for Windows PowerShell web requests.
	The certificate policy type is compiled once per session.
	Outputs the previously configured certificate policy, which should be restored once requests complete.

	.EXAMPLE
	$CertificatePolicy = Skip-CertificateCheck

	Skips certificate validation, saving the previous certificate policy to $CertificatePolicy.

	#>

	if ($PSEdition -ne 'Core') {

		if (-not ('CredentialRetriever.TrustAllCertificatePolicy' -as [type])) {

			Add-Type -TypeDefinition @'
namespace CredentialRetriever
{
	public class TrustAllCertificatePolicy : System.Net.ICertificatePolicy
	{
		public bool CheckValidationResult(System.Net.ServicePoint sp, System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
		{
			return true;
		}
	}
}
'@

		}

		[System.Net.ServicePointManager]::CertificatePolicy
		[System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName CredentialRetriever.TrustAllCertificatePolicy

	}

}
