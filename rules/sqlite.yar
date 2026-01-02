/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
      - Joan Bono <@joan_bono>
*/

rule sqlite: SQLITE
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00}

    condition:
       $a at 0
}

rule windows_thumbnail: WTBDB
{
    meta:
        author = "Joan Bono"

    strings:
	$a = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
       $a at 0
}

rule quartus_database: QRDB
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 51 75 61 72 74 75 73 5F 56 65 72 73 69 6F 6E 20 }

    condition:
	$a at 0
}
