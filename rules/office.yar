/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
      - Joan Bono <@joan_bono>
*/

rule doc: DOC
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {CF 11 E0 A1 B1 1A E1 00}

    condition:
       $a at 0
}

rule excel_2007: XLSX
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 50 4b 03 04 }

    condition:
       $a at 0
}

rule excel_2003: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 00 }

    condition:
       $a at 0
}

rule excel_XML: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 3C 3F 78 6D 6C 20 76 }

    condition:
       $a at 0
}

rule excel_OS2worksheet: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 09 00 04 00 06 00 }

    condition:
       $a at 0
}

rule excel_OrthoTrack: XLS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 56 65 72 73 69 6F 6E 09 }

    condition:
       $a at 0
}

