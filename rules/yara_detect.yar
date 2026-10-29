/*
    Regras YARA Educacionais para Detecção de Assinaturas e Padrões Suspeitos
    DIO - Formação Cibersegurança / Blue Team
*/

rule Detect_Suspicious_Keyboard_Hooking
{
    meta:
        description = "Detecta referências a bibliotecas e APIs frequentemente usadas para captura de teclado não autorizada"
        author = "DIO Cybersecurity Lab"
        severity = "High"
        mitre_technique = "T1056.001"

    strings:
        $api_hook1 = "SetWindowsHookEx" ascii wide nocase
        $api_hook2 = "GetAsyncKeyState" ascii wide nocase
        $lib_pynput = "pynput.keyboard" ascii nocase
        $lib_keyboard = "import keyboard" ascii nocase
        $log_pattern = "Key.space" ascii nocase

    condition:
        ($api_hook1 or $api_hook2) or 
        ($lib_pynput and $log_pattern) or 
        ($lib_keyboard and $log_pattern)
}

rule Detect_Mass_File_Encryption_Indicators
{
    meta:
        description = "Identifica padrões comumente encontrados em rotinas de modificação em lote e notas de extorsão"
        author = "DIO Cybersecurity Lab"
        severity = "Critical"
        mitre_technique = "T1486"

    strings:
        $ransom_note1 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $ransom_note2 = "SEUS ARQUIVOS FORAM CRIPTOGRAFADOS" ascii wide nocase
        $ransom_note3 = "HOW TO DECRYPT" ascii wide nocase
        $crypto_fernet = "from cryptography.fernet import Fernet" ascii nocase
        $bulk_walk = "os.walk" ascii nocase

    condition:
        ($crypto_fernet and $bulk_walk and any of ($ransom_note*)) or
        (2 of ($ransom_note*))
}
