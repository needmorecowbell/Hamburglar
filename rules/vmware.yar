/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Joan Bono <@joan_bono>
*/

rule vmdk: VMDK
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {4B 44 4D 56}

    condition:
       $a at 0
}

rule vmem: VMEM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {53 ff 00 f0}

    condition:
       $a at 0
}

rule nvram: NVRAM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {4D 52 56 4E}

    condition:
       $a at 0
}
 
rule vmx: VMX
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {2E 65 6E 63 6F 64 69 6E 67 20 3D 20 22}

    condition:
       $a at 0
}

rule vmxf: VMXF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31}

    condition:
       $a at 0
}

rule vmss: VMSS
{
    meta:
        author = "Joan Bono"

    strings:
        $a = {d2 be d2 be 08 00 00 00 66}

    condition:
       $a at 0
}
