/*
    Description: This finds the magics on individual files.
    Disclaimer: This can though false positives.

    Contributors:
      - Jaume Martin <@Xumeiquer>
*/

rule skype_user_data: SKYPE
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {6C 33 33 6C}

    condition:
       $a at 0
}
