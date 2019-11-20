/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Joan Bono <@joan_bono>
*/

rule exe: EXE
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4D 5A }
	$b = "!This program cannot be run in DOS mode."

    condition:
       $a at 0 and for all of ($b): (@ > @a)
}

rule elf64: ELF64
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 7F 45 4C 46 }
	$b = "linux_amd64"
	$c = "linux-x86-64"

    condition:
       $a at 0 and ($b or $c)
}

