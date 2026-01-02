/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
      - Joan Bono <@joan_bono>
*/

rule videocd: VCD
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58}

    condition:
       $a at 0
}

rule ogg: OGG
{
    meta:
        author = "Jaume Martin"
        file_info = "Ogg Vorbis Codec"

    strings:
        $a = {4F 67 67 53 00 02 00 00 00 00 00 00 00 00}

    condition:
       $a at 0
}

rule avi: AVI
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 52 49 46 46 }

    condition:
       $a at 0
}

rule mkv: MKV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 1A 45 DF A3 }

    condition:
       $a at 0
}

rule flv: FLV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 46 4C 56 01 }

    condition:
       $a at 0
}

rule wmv: WMV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }

    condition:
       $a at 0
}

rule mpg2: MPG
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 00 00 01 BA 44 }

    condition:
       $a at 0
}

rule mpg4: MP4
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 00 00 00 14 66 74 79 70 69 73 6F 6D 00 00 00 01 }

    condition:
       $a at 0
}

rule mov: MOV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4B 41 4D 76 }

    condition:
       $a at 0
}

rule real_media_stream: RM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 2E 52 4D 46 00 00 00 12 00 }

    condition:
       $a at 0
}

rule real_media_variable_bitrate: RMVB
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 2E 52 4D 46 }

    condition:
       $a at 0
}

rule raw_h264: H264
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 00 00 00 01 67 64 00 1F AC 34 E2 40 B4 11 7E E1 }

    condition:
       $a at 0
}

rule magic_lantern_video: MLV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4D 4C 56 49 }

    condition:
       $a at 0
}

rule webm: WEBM
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 1A 45 DF A3 }

    condition:
       $a at 0
}

rule vob: VOB
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { FF FF FF 5D 00 00 00 02 00 01 00 00 00 FC FF 35 }

    condition:
       $a at 0
}

rule dirac: DRC
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 42 42 43 44 }

    condition:
       $a at 0
}


rule gif_animated: GIF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 47 49 46 38 39 61 }

    condition:
       $a at 0
}

rule anime_music_video: AMV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 52 49 46 46 }

    condition:
       $a at 0
}

rule material_exchange_music: MXF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02 }

    condition:
       $a at 0
}

rule picasa_material_exchange_music: MXF
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 3C 43 54 72 61 6E 73 54 69 6D 65 6C 69 6E 65 3E }

    condition:
       $a at 0
}

rule id_software_game_video: ROQ
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 84 10 FF FF FF FF 1E 00 }

    condition:
       $a at 0
}

rule nullsoft_streaming_video: NSV
{
    meta:
        author = "Joan Bono"

    strings:
        $a = { 4E 53 56 }

    condition:
       $a at 0
}


