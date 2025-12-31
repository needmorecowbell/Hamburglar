/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule win_register: REG SUD
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {52 45 47 45 44 49 54}

    condition:
       $a at 0
}

rule win_hive: REG HIVE
{
        meta:
            author = "Jaume Martin"
        strings:
            $a = { 72 65 67 66 }
        condition:
            $a at 0
}
