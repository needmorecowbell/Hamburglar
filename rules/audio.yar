/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
      - Rafa Bono <@rafa_bono>
*/

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

rule aac: AAC
{
    meta:
        author = "Rafa Bono"
        file_info = "Advanced Audio Coding"

    strings:
        $a = {41 41 43 00 01 00}

    condition:
       $a at 0
}

rule au: AU
{
    meta:
        author = "Rafa Bono"
        file_info = "Audacity Audio"

    strings:
        $a = {64 6E 73 2E}

    condition:
       $a at 0
}

rule next_au_format: AU
{
    meta:
        author = "Rafa Bono"
        file_info = "NeXT Audio Format"

    strings:
        $a = {2E 73 6E 64 00 00 00}

    condition:
       $a at 0
}

rule aax: AAX
{
    meta:
        author = "Rafa Bono"
        file_info = "Audible Enhanced Audio"

    strings:
        $a = {00 00 00 24 66 74 79 70 61 61 78 20 00 00 00 01}

    condition:
       $a at 0
}

rule act: ACT
{
    meta:
        author = "Rafa Bono"
        file_info = "Cartooners Actor"

    strings:
        $a = {00 10 46 00 00 00 77 07 85 0C}

    condition:
       $a at 0
}

rule aiff: AIFF
{
    meta:
        author = "Rafa Bono"
        file_info = "Audio Interchange File Format"

    strings:
        $a = {46 4F 52 4D}

    condition:
       $a at 0
}

rule amr: AMR
{
    meta:
        author = "Rafa Bono"
        file_info = "Adaptive Multi Rate Encoded Audio"

    strings:
        $a = {23 21 41 4D 52 0A}

    condition:
       $a at 0
}

rule ape: APE
{
    meta:
        author = "Rafa Bono"
        file_info = "Monkey's Audio"

    strings:
        $a = {4D 41 43 20}

    condition:
       $a at 0
}

rule awb: AWB
{
    meta:
        author = "Rafa Bono"
        file_info = "Adaptive Multi-Rate Wideband ACELP codec"

    strings:
        $a = {23 21 41 4D 52 2D 57 42}

    condition:
       $a at 0
}

rule dss: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Digital Sound Studio module"

    strings:
        $a = {4D 4D 55 32}

    condition:
       $a at 0
}

rule dss_v2: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Digital Speech Standard audio (v2)"

    strings:
        $a = {02 64 73 73}

    condition:
       $a at 0
}

rule dss_v3: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Digital Speech Standard audio (v3)"

    strings:
        $a = {03 64 73 73}

    condition:
       $a at 0
}

rule dream_station_1_module: DSS
{
    meta:
        author = "Rafa Bono"
        file_info = "Dream Station 1.0 module"

    strings:
        $a = {44 53 46 6D 74 31 0D 0A}

    condition:
       $a at 0
}

rule dvf: DVF
{
    meta:
        author = "Rafa Bono"
        file_info = "Sony Compressed Voice File"

    strings:
        $a = {4D 53 5F 56 4F 49 43 45}

    condition:
       $a at 0
}

rule flac: FLAC
{
    meta:
        author = "Rafa Bono"
        file_info = "Free Lossless Audio Codec"

    strings:
        $a = {66 4C 61 43}

    condition:
       $a at 0
}

rule gsm: GSM
{
    meta:
        author = "Rafa Bono"
        file_info = "US Robotics GSM audio"

    strings:
        $a = {52 49 46 46}

    condition:
       $a at 0
}

rule m4a: M4A
{
    meta:
        author = "Rafa Bono"
        file_info = "Apple Lossless Audio Codec"

    strings:
        $a = {00 00 00 20 66 74 79 70 4D 34 41 20 00 00 00 00}

    condition:
       $a at 0
}

rule mmf: MMF
{
    meta:
        author = "Rafa Bono"
        file_info = "Yamaha SMAF Synthetic music Mobile Application Format"

    strings:
        $a = {4D 4D 4D 44}

    condition:
       $a at 0
}

rule mp3: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "MP3 Audio"

    strings:
        $a = {49 44 33}

    condition:
       $a at 0
}

rule mp3_album_wrap: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "MP3 AlbumWrap archive"

    strings:
        $a = {49 44 33 03 00 00 00 00 0A 23 54 49 54 32 00 00}

    condition:
       $a at 0
}

rule mp3_gogo_encoded: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "GoGo encoded MP3 audio"

    strings:
        $a = {FF FB 90}
        $b = {49 44 33 }

    condition:
       $a at 0 or $b at 0
}

rule mp3_hd: MP3
{
    meta:
        author = "Rafa Bono"
        file_info = "MP3 HD audio"

    strings:
        $a = {49 44 33 03 00 00 00}

    condition:
       $a at 0
}

rule mpc_gen: MPC
{
    meta:
        author = "Rafa Bono"
        file_info = "Musepack encoded audio (generic)"

    strings:
        $a = {4D 50 2B}

    condition:
       $a at 0
}

rule mpc_sv7: MPC
{
    meta:
        author = "Rafa Bono"
        file_info = "Musepack encoded audio (SV7)"

    strings:
        $a = {4D 50 2B 07}

    condition:
       $a at 0
}

rule mpc_sv8: MPC
{
    meta:
        author = "Rafa Bono"
        file_info = "Musepack encoded audio (SV8)"

    strings:
        $a = {4D 50 43 4B 53 48 0F}

    condition:
       $a at 0
}

rule msv: MSV
{
    meta:
        author = "Rafa Bono"
        file_info = "Sony Compressed Voice File"

    strings:
        $a = {4D 53 5F 56 4F 49 43 45}

    condition:
       $a at 0
}

rule opus: OPUS
{
    meta:
        author = "Rafa Bono"
        file_info = "Opus compressed audio"

    strings:
        $a = {4F 67 67 53}

    condition:
       $a at 0
}

rule ra: RA
{
    meta:
        author = "Rafa Bono"
        file_info = "Real Audio"

    strings:
        $a = {2E 72 61 FD 00}
        $b = {2E 52 4D 46 00 00 00 12 00}

    condition:
       $a at 0 or $b at 0
}

rule raw: RAW
{
    meta:
        author = "Rafa Bono"
        file_info = "Rdos Raw OPL Capture music"

    strings:
        $a = {52 41 57 41 44 41 54 41}

    condition:
       $a at 0
}
 
rule tta: TTA
{
    meta:
        author = "Rafa Bono"
        file_info = "TTA lossless compressed audio"

    strings:
        $a = {54 54 41}

    condition:
       $a at 0
}

rule vox_magica_voxel: VOX
{
    meta:
        author = "Rafa Bono"
        file_info = "MagicaVoxel file format"

    strings:
        $a = {56 4F 58 20}

    condition:
       $a at 0
}

rule vox_voxware: VOX
{
    meta:
        author = "Rafa Bono"
        file_info = "VoxWare MetaVoice encoded audio"

    strings:
        $a = {52 49 46 46}

    condition:
       $a at 0
}
