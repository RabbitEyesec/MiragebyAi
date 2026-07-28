rule Mirage_EICAR_Test_File
{
  meta:
    source = "Mirage controlled test fixture"
    version = "1.0"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar
}

rule Mirage_Encoded_PowerShell
{
  meta:
    source = "Mirage defensive baseline"
    version = "1.0"
  strings:
    $a = /powershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b/i
  condition:
    $a
}
