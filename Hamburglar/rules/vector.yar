/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Joan Bono <@joan_bono>
*/

rule ai: AI
{
    meta:
        author = "Joan Bono"
        file_info = "Adobe Illustrator"

    strings:
        $a = {25 21 50 53 2D}

    condition:
       $a at 0
}

rule ai_compressed: AI
{
    meta:
        author = "Joan Bono"
        file_info = "Adobe Illustrator Comrpessed"

    strings:
        $a = {41 69 02}

    condition:
       $a at 0
}

rule corel_draw_graohic: CDR
{
    meta:
        author = "Joan Bono"
        file_info = "Corel Draw Document"

    strings:
        $a = {52 49 46 46}

    condition:
       $a at 0
}

rule corel_draw_compressed: CDR
{
    meta:
        author = "Joan Bono"
        file_info = "Corel Draw Document Compressed"

    strings:
        $a = {50 4B 03 04}

    condition:
       $a at 0
}

rule gem: GEM
{
    meta:
        author = "Joan Bono"
        file_info = "Graphics Environment Manager"

    strings:
        $a = {FF FF 18}

    condition:
       $a at 0
}

rule hpgl: HPGL
{
    meta:
        author = "Joan Bono"
        file_info = "HP Graphics Language"

    strings:
        $a = {49 4E 3B}

    condition:
       $a at 0
}

rule hvif: HVIF
{
    meta:
        author = "Joan Bono"
        file_info = "Haiku Vector Icon Format"

    strings:
        $a = {6E 63 69 66}

    condition:
       $a at 0
}

rule odg: ODG
{
    meta:
        author = "Joan Bono"
        file_info = "Open Document Graphics document"

    strings:
        $a = {50 4B 03 04}

    condition:
       $a at 0
}

rule povray: POVRAY
{
    meta:
        author = "Joan Bono"
        file_info = "Persistence of Vision State File"

    strings:
        $a = {50 4F 56 2D 52 61 79 20 52 65 6E 64 65 72 20 53}

    condition:
       $a at 0
}

rule pgml: PGML
{
    meta:
        author = "Joan Bono"
        file_info = "Precission Graphics Markup Language"

    strings:
        $a = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31}

    condition:
       $a at 0
}

rule pgf: PGF
{
    meta:
        author = "Joan Bono"
        file_info = "Progressive Graphics File bitmap"

    strings:
        $a = {50 47 46 01 10 00}

    condition:
       $a at 0
}

rule gis: GIS
{
    meta:
        author = "Joan Bono"
        file_info = "Erdas bitmap"

    strings:
        $a = {48 45 41 44 37 34 00 00 03 00 00 00 00 00 00 00}

    condition:
       $a at 0
}

rule rip: RIP
{
    meta:
        author = "Joan Bono"
        file_info = "Rocky Interlace Picture"

    strings:
        $a = {52 49 50}

    condition:
       $a at 0
}

rule wmf: WMF
{
    meta:
        author = "Joan Bono"
        file_info = "Windows Metafile"

    strings:
        $a = {01 00 09 00}
        $b = {D7 CD C6 9A 00 00}

    condition:
       $a at 0 or $b at 0
}

rule xar: XAR
{
    meta:
        author = "Joan Bono"
        file_info = "Xara vector drawing"

    strings:
        $a = {58 41 52 41 A3 A3 0D}

    condition:
       $a at 0
}

rule amf: AMF
{
    meta:
        author = "Joan Bono"
        file_info = "Additive Manufacturing File Format"

    strings:
        $a = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31}

    condition:
       $a at 0
}

rule blend: BLEND
{
    meta:
        author = "Joan Bono"
        file_info = "Blender 3D File"

    strings:
        $a = {42 4C 45 4E 44 45 52}

    condition:
       $a at 0
}

rule dgn: DGN
{
    meta:
        author = "Joan Bono"
        file_info = "Bentley MicroStation CAD drawing"

    strings:
        $a = {D0 CF 11 E0 A1 B1 1A E1 00}

    condition:
       $a at 0
}

rule dwf: DWF
{
    meta:
        author = "Joan Bono"
        file_info = "AutoDesk Design Web Format"

    strings:
        $a = {28 44 57 46 20 56}

    condition:
       $a at 0
}

rule dwg: DWG
{
    meta:
        author = "Joan Bono"
        file_info = "AutoDesk AutoCAD Drawing"

    strings:
        $a = {41 43 31 30 31 35} /* 2000-2002 */
        $b = {41 43 31 30 31 38} /* 2004-2006 */
        $c = {41 43 31 30 32 31} /* 2007-2009 */
        $d = {41 43 31 30 32 34} /* 2010-2012 */
        $e = {41 43 31 30 32 37} /* 2013-2016 */
        $f = {4D 43 30 2E 30} /* AutoCAD R1.0 */
        $g = {41 43 31 2E 32} /* AutoCAD R1.2 */
        $h = {41 43 31 2E 34 30} /* AutoCAD R1.40 */
        $i = {41 43 31 30 30 36} /* AutoCAD R10 */
        $j = {41 43 31 30 30 39} /* AutoCAD R11-12 */
        $k = {41 43 31 30 31 30} /* AutoCAD R13 (sub 10) */
        $l = {41 43 31 30 31 31} /* AutoCAD R13 (sub 11) */
        $m = {41 43 31 30 31 32} /* AutoCAD R13 */
        $n = {41 43 31 30 31 33} /* AutoCAD R13 */

    condition:
        for any of ($*) : ( $ at 0 )
}

rule dxf: DXF
{
    meta:
        author = "Joan Bono"
        file_info = "AutoDesk AutoCAD Exchange Format"

    strings:
        $a = {41 75 74 6F 43 41 44 20 42 69 6E 61 72 79 20 44}

    condition:
       $a at 0
}

rule hsf: HSF
{
    meta:
        author = "Joan Bono"
        file_info = "HOOPS 3D Stream Format"

    strings:
        $a = {3B 3B 20 48 53 46 20 56}

    condition:
       $a at 0
}

rule jt: JT
{
    meta:
        author = "Joan Bono"
        file_info = "JT 3D Visualization format"

    strings:
        $a = {56 65 72 73 69 6F 6E 20}

    condition:
       $a at 0
}

rule ma: MA
{
    meta:
        author = "Joan Bono"
        file_info = "Maya ASCII Format"

    strings:
        $a = {2F 2F 4D 61 79 61 20 41 53 43 49 49}

    condition:
       $a at 0
}

rule mb: MB
{
    meta:
        author = "Joan Bono"
        file_info = "Maya Binary Scene"

    strings:
        $a = {46 4F 52 34}

    condition:
       $a at 0
}

rule obg: OBJ
{
    meta:
        author = "Joan Bono"
        file_info = "AliaslWavefront File Format"

    strings:
        $a = {23 20 4D 61 78 32 4F 62 6A 20 56 65 72 73 69 6F} /* 3D Max */
        $b = {23 57 61 76 65 66 72 6F 6E 74 20 4F 42 4A 20 66} /* Hexagon */
        $c = {41 43 4D 54 00 00} /* X-CAD Modifier */
        $d = {23 20 42 6C 65 6E 64 65 72} /* Blender 3D */

    condition:
       for any of ($*) : ( $ at 0 )
}

rule prc: PRC
{
    meta:
        author = "Joan Bono"
        file_info = "Picture Gear Bitmap"

    strings:
        $a = {42 69 74 6D 61 70}

    condition:
       $a at 0
}

rule skp: SKP
{
    meta:
        author = "Joan Bono"
        file_info = "Google SketchUp"

    strings:
        $a = {FF FE FF 0E 53 00 6B 00 65 00 74 00 63 00 68 00}

    condition:
       $a at 0
}

rule stl: STL
{
    meta:
        author = "Joan Bono"
        file_info = "STereoLithography"

    strings:
        $a = {61 6C 69 62 72 65 20 73 74 6C 20 62 69 6E 61 72} /* Alibre */
        $b = {53 54 4C 42 20 41 54 46 20} /* ATF */
        $c = {41 75 74 6F 43 41 44 20 73 6F 6C 69 64 00} /* AutoCAD */
        $d = {45 78 70 6F 72 74 65 64 20 66 72 6F 6D 20} /* Blender 3D */
        $e = {53 54 4C 20 4F 75 74 70 75 74 20 66 72 6F 6D 20} /* Geomagic Studio */
        $f = {53 54 4C 42 20 41 53 4D 20} /* Inventor */
        $g = {53 54 4C 20 46 69 6C 65 20 63 72 65 61 74 65 64} /* netfabb */
        $h = {52 68 69 6E 6F 63 65 72 6F 73 20 42 69 6E 61 72} /* Rhinoceros */
        $i = {62 69 6E 61 72 79 20 73 74 6C 20 66 69 6C 65 20} /* STereo Lithography */
        $j = {73 6F 6C 69 64 20} /* STereo Lithography ASCII */

    condition:
       for any of ($*) : ( $ at 0 )
}

rule u3d: U3D
{
    meta:
        author = "Joan Bono"
        file_info = "Universal 3D"

    strings:
        $a = {55 33 44 00}

    condition:
       $a at 0
}

rule xaml: XAML
{
    meta:
        author = "Joan Bono"
        file_info = "Microsoft Extensible Application Markup Language"

    strings:
        $a = {EF BB BF 3C}

    condition:
       $a at 0
}

rule x3d: X3D
{
    meta:
        author = "Joan Bono"
        file_info = "Extensible 3D Vector Graphics"

    strings:
        $a = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D}

    condition:
       $a at 0
}

rule vector3d: Vector3D
{
    meta:
        author = "Joan Bono"
        file_info = "VersaCAD Drawing"

    strings:
        $a = {01 00 32 00 28 00 00 00}

    condition:
       $a at 0
}

rule _3dm: _3DM
{
    meta:
        author = "Joan Bono"
        file_info = "3D Model"

    strings:
        $a = {43 61 64 65 6E 74 20 33 44 20 4D 6F 64 65 6C 20} /* Cadent 3D Model */
        $b = {33 44 20 47 65 6F 6D 65 74 72 79 20 46 69 6C 65} /* Rhinoceros 3D Model */

    condition:
       $a at 0 or $b at 0
}

rule _3dxml: _3DXML
{
    meta:
        author = "Joan Bono"
        file_info = "3D XML Files"

    strings:
        $a = {3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31}

    condition:
       $a at 0
}

rule _3dxml_compressed: _3DXML
{
    meta:
        author = "Joan Bono"
        file_info = "3D XML Files Compressed"

    strings:
        $a = {50 4B 03 04}

    condition:
       $a at 0
}