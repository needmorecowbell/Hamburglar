/*
    Description: This finds the magics on dump files, like raw dd image.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule pgp_wde: PGP WDE
{
    meta:
        author = "Jaume Martin"
        description = "PGP Whole Disk Encryption"
    strings:
        $a = {50 47 50 64 4D 41 49 4E}

    condition:
       $a at 0
}

rule pgp_skr: PGP SKR
{
    meta:
        author = "Jaume Martin"
        description = "Private keyring"
    strings:
        $a = {95 00}
        $b = {95 01}

    condition:
       $a at 0 or $b at 0
}

rule pgp_pkr: PGP PKR
{
    meta:
        author = "Jaume Martin"
        description = "Public keyring"
    strings:
        $a = {99 01}

    condition:
       $a at 0
}

rule x509: DER x509
{
    meta:
        author = "Jaume Martin"
        
    strings:
        $a = {30 82}

    condition:
       $a at 0
}
