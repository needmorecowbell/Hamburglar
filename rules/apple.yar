/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Joan Bono <@joan_bono>
*/

rule plist: PLIST
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 62 70 6c 69 73 74 30 30 }

    condition:
       $a at 0
}

rule apple_bom: CAR
{
    meta:
        author = "Joan Bono"

    strings:
	$a = { 42 4f 4d 53 74 6f 72 65 }

    condition:
       $a at 0
}

rule apple_nib: NIB
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 4e 49 42 41 72 63 68 69 76 65 01 }

    condition:
	$a at 0
}

rule apple_dylib: DYLIB
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { cf fa ed fe 0c 00 00 01 }

    condition:
	$a at 0
}

rule apple_sinf: SINF
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 00 00 04 20 73 69 6e 66 }

    condition:
	$a at 0
}

rule apple_supf: SUPF
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 03 34 30 35 00 00 07 a8 }

    condition:
	$a at 0
}

rule apple_supp: SUPP
{
    meta:
	author = "Joan Bono"

    strings:
	$a = { 01 34 30 35 2b 8d 5c 4c 24 18 d2 5f }

    condition:
	$a at 0
}

