/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Joan Bono <@joan_bono>
*/

rule gif_bitmap: GIF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 47 49 46 }

    condition:
       $a at 0
}

rule gif87a_bitmap: GIF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 47 49 46 38 37 61 }

    condition:
       $a at 0
}

rule gif89a_bitmap: GIF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 47 49 46 38 39 61 }

    condition:
       $a at 0
}