"""
Monitor de Integridade de Arquivos (FIM - File Integrity Monitor)
Projeto Educacional DIO - Segurança Defensiva (Blue Team)

Este script atua exclusivamente como ferramenta DEFENSIVA de monitoramento:
1. Mapeia um diretório selecionado.
2. Calcula o hash SHA-256 de cada arquivo.
3. Alerta o analista caso ocorra modificação, adição ou remoção não autorizada,
   simulando como ferramentas EDR e SIEM detectam alterações anômalas no disco.
"""

import os
import hashlib
import json
import time

DB_FILE = "baseline_hashes.json"

def calculate_sha256(filepath):
    """Calcula o hash SHA-256 do arquivo informado."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None

def build_baseline(directory_to_scan):
    """Gera uma linha de base (baseline) dos arquivos no diretório."""
    baseline = {}
    print(f"[*] Escaneando diretório para gerar baseline: {directory_to_scan}")
    
    for root, _, files in os.walk(directory_to_scan):
        for filename in files:
            filepath = os.path.join(root, filename)
            # Ignora o próprio arquivo de base de dados
            if filename == DB_FILE:
                continue
            file_hash = calculate_sha256(filepath)
            if file_hash:
                baseline[filepath] = {
                    "hash": file_hash,
                    "timestamp": time.time()
                }
    
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=4)
        
    print(f"[+] Baseline gerada com sucesso! {len(baseline)} arquivos catalogados em {DB_FILE}.")

def monitor_integrity(directory_to_scan):
    """Compara os arquivos atuais com a baseline para detectar anomalias."""
    if not os.path.exists(DB_FILE):
        print(f"[-] Arquivo de baseline ({DB_FILE}) não encontrado. Gere a baseline primeiro.")
        return

    with open(DB_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    print(f"[*] Iniciando verificação de integridade defensiva em: {directory_to_scan}")
    current_files = set()
    alerts = 0

    for root, _, files in os.walk(directory_to_scan):
        for filename in files:
            filepath = os.path.join(root, filename)
            if filename == DB_FILE:
                continue
            current_files.add(filepath)
            current_hash = calculate_sha256(filepath)

            if filepath not in baseline:
                print(f"[ALERTA DE SEGURANÇA] Novo arquivo não mapeado detectado: {filepath}")
                alerts += 1
            elif current_hash != baseline[filepath]["hash"]:
                print(f"[ALERTA DE SEGURANÇA] Arquivo MODIFICADO detectado: {filepath}")
                print(f"   -> Hash Esperado: {baseline[filepath]['hash']}")
                print(f"   -> Hash Atual:    {current_hash}")
                alerts += 1

    # Checar arquivos deletados
    for filepath in baseline:
        if filepath not in current_files and os.path.exists(os.path.dirname(filepath)):
            print(f"[ALERTA DE SEGURANÇA] Arquivo REMOVIDO detectado: {filepath}")
            alerts += 1

    if alerts == 0:
        print("[+] Integridade verificada. Nenhuma alteração anômala detectada.")
    else:
        print(f"[!] Total de alertas de integridade emitidos: {alerts}")

if __name__ == "__main__":
    import sys
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print("=" * 60)
    print("  DIO Defesa Cibernética - File Integrity Monitor (FIM)")
    print("=" * 60)
    
    if not os.path.exists(DB_FILE):
        build_baseline(target_dir)
    else:
        monitor_integrity(target_dir)
