include "example/pe.yar"
include 'example/imports.yar'

rule pe_with_winsock
{

    condition:
        is_pe and has_winsock 
}
