/*
    Default YARA rule set for the AI-Powered OSINT Investigation Platform.

    Drop additional .yar / .yara files into this same directory to extend
    coverage - YaraScanner compiles every rule file found here at process
    startup (see backend/app/integrations/file/yara_scanner.py). No code
    changes are required to add more rules.
*/

rule EICAR_Test_File
{
    meta:
        description = "Detects the industry-standard EICAR antivirus test string"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "info"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}

rule Suspicious_PE_Process_Injection_APIs
{
    meta:
        description = "PE file importing a combination of APIs commonly used for process injection"
        severity = "high"

    strings:
        $mz = "MZ"
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtUnmapViewOfSection" ascii

    condition:
        $mz at 0 and 2 of ($api1, $api2, $api3, $api4)
}

rule Suspicious_PE_AntiDebug_APIs
{
    meta:
        description = "PE file importing common anti-debugging / anti-analysis APIs"
        severity = "medium"

    strings:
        $mz = "MZ"
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugStringA" ascii

    condition:
        $mz at 0 and 2 of ($api1, $api2, $api3, $api4)
}

rule Office_Macro_Enabled_Document
{
    meta:
        description = "Legacy OLE-format Office document containing an embedded VBA macro project"
        severity = "medium"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $vba_dir = "VBA" wide
        $vba_dir2 = "Macros" ascii

    condition:
        $ole_magic at 0 and ($vba_dir or $vba_dir2)
}

rule OOXML_Macro_Enabled_Document
{
    meta:
        description = "Modern OOXML (docx/xlsx/pptx) document repackaged with a vbaProject.bin macro payload"
        severity = "medium"

    strings:
        $zip_magic = { 50 4B 03 04 }
        $vba_project = "vbaProject.bin" ascii

    condition:
        $zip_magic at 0 and $vba_project
}

rule Suspicious_Embedded_PowerShell_EncodedCommand
{
    meta:
        description = "File containing PowerShell -EncodedCommand / -enc invocation strings, common in obfuscated malware droppers"
        severity = "high"

    strings:
        $s1 = "-EncodedCommand" nocase ascii wide
        $s2 = "-enc " nocase ascii wide
        $s3 = "FromBase64String" ascii wide
        $s4 = "IEX(" nocase ascii wide

    condition:
        any of them
}

rule Suspicious_JavaScript_Obfuscation
{
    meta:
        description = "Script content using common JavaScript obfuscation / dynamic-eval patterns"
        severity = "medium"

    strings:
        $eval1 = "eval(unescape(" ascii
        $eval2 = "eval(atob(" ascii
        $eval3 = "String.fromCharCode(" ascii
        $wscript = "WScript.Shell" ascii

    condition:
        2 of them
}

rule Embedded_Executable_In_Document
{
    meta:
        description = "Non-PE document container that itself embeds an MZ/PE header, indicating a bundled executable payload"
        severity = "high"

    strings:
        $pdf_magic = "%PDF-"
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip_magic = { 50 4B 03 04 }
        $mz_embedded = "MZ"

    condition:
        ($pdf_magic at 0 or $ole_magic at 0 or $zip_magic at 0)
        and $mz_embedded
        and #mz_embedded > 1
}
