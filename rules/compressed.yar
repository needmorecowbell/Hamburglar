/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule _7z: _7z
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {37 7A BC AF 27 1C}

    condition:
       $a at 0
}

rule rar: rar
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {52 61 72 21 1A 07 00}
        $b = {52 61 72 21 1A 07 01 00}

    condition:
    $a at 0 or $b at 0
}

rule tar: tar
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {75 73 74 61 72 00 30 30}
        $b = {75 73 74 61 72 20 20 00}

    condition:
    $a at 0 or $b at 0
}

rule gzip: gzip
{
    meta:
        author = "Jaume martin"

    strings:
        $a = {1F 8B}
        $b = {1F 8B}

    condition:
    $a at 0 or $b at 0
}
