#!/usr/bin/env python3

"""
Exemplo de uso do CyberprotectAnalyzer.

Este exemplo demonstra como usar o CyberprotectAnalyzer para consultar
a API ThreatScore da Cyberprotect e obter informações sobre ameaças.

Uso:
    python cyberprotect_example.py --data "example.com" --data-type "domain" --execute
    python cyberprotect_example.py --data "1.2.3.4" --data-type "ip" --execute
    python cyberprotect_example.py --data "https://malicious-site.com" --data-type "url" --execute
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

# Adicionar o diretório src ao path para importar o módulo
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cyberprotect import CyberprotectAnalyzer


def main():
    """Função principal do exemplo."""
    parser = argparse.ArgumentParser(
        description="Exemplo de uso do CyberprotectAnalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --data "example.com" --data-type "domain" --execute
  %(prog)s --data "1.2.3.4" --data-type "ip" --execute
  %(prog)s --data "https://malicious-site.com" --data-type "url" --execute
  %(prog)s --data "d41d8cd98f00b204e9800998ecf8427e" --data-type "hash" --execute
  %(prog)s --data "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --data-type "user-agent" --execute
""",
    )

    # Argumentos de dados (obrigatórios)
    parser.add_argument(
        "--data", required=True, help="Dados para analisar (domínio, IP, URL, hash ou user-agent)"
    )
    parser.add_argument(
        "--data-type",
        required=True,
        choices=["domain", "ip", "url", "hash", "user-agent"],
        help="Tipo de dados a serem analisados",
    )

    # Portões de segurança (OBRIGATÓRIO)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Executar análise real (obrigatório para operações reais)",
    )

    # Argumentos opcionais
    parser.add_argument(
        "--tlp",
        type=int,
        default=2,
        choices=[0, 1, 2, 3],
        help="Traffic Light Protocol level (0-3, padrão: 2)",
    )
    parser.add_argument(
        "--pap",
        type=int,
        default=2,
        choices=[0, 1, 2, 3],
        help="Permissible Actions Protocol level (0-3, padrão: 2)",
    )
    parser.add_argument("--verbose", action="store_true", help="Exibir informações detalhadas")
    parser.add_argument(
        "--output-format",
        choices=["json", "pretty"],
        default="pretty",
        help="Formato de saída (padrão: pretty)",
    )

    args = parser.parse_args()

    # Verificação de modo dry-run
    if not args.execute:
        print("🔒 Modo dry-run ativo. Use --execute para realizar análise real.")
        print(f"📊 Dados a serem analisados: {args.data} (tipo: {args.data_type})")
        print(
            "💡 Exemplo: python cyberprotect_example.py --data 'example.com' --data-type 'domain' --execute"
        )
        return

    try:
        # Configurar entrada de dados
        worker_input = WorkerInput(
            data_type=args.data_type,
            data=args.data,
            tlp=args.tlp,
            pap=args.pap,
            config=WorkerConfig(
                check_tlp=True,
                max_tlp=args.tlp,
                check_pap=True,
                max_pap=args.pap,
                auto_extract=True,
                secrets={},  # Cyberprotect não requer API key
            ),
        )

        if args.verbose:
            print("🔍 Iniciando análise com CyberprotectAnalyzer...")
            print(f"📊 Dados: {args.data}")
            print(f"🏷️  Tipo: {args.data_type}")
            print(f"🚦 TLP: {args.tlp}, PAP: {args.pap}")
            print("" + "-" * 50)

        # Executar análise
        analyzer = CyberprotectAnalyzer(worker_input)
        result = analyzer.run()

        # Exibir resultados
        if args.output_format == "json":
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        else:
            print_pretty_result(result, args.verbose)

    except Exception as e:
        print(f"❌ Erro durante a análise: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


def print_pretty_result(result, verbose=False):
    """Imprime o resultado de forma formatada."""
    data = result.to_dict()

    print("\n" + "=" * 60)
    print("🛡️  RESULTADO DA ANÁLISE CYBERPROTECT")
    print("=" * 60)

    print(f"📊 Observable: {data.get('observable', 'N/A')}")
    print(f"⚖️  Veredicto: {data.get('verdict', 'N/A').upper()}")

    # Exibir taxonomia
    taxonomies = data.get("taxonomy", [])
    if taxonomies:
        print("\n🏷️  Taxonomia:")
        for tax in taxonomies:
            level = tax.get("level", "info")
            namespace = tax.get("namespace", "N/A")
            predicate = tax.get("predicate", "N/A")
            value = tax.get("value", "N/A")

            emoji = {"malicious": "🔴", "suspicious": "🟡", "safe": "🟢", "info": "🔵"}.get(
                level, "⚪"
            )

            print(f"   {emoji} {namespace}.{predicate}: {value}")

    # Exibir erros se houver
    if "error" in data:
        print(f"\n⚠️  Erro: {data['error']}")

    # Exibir resposta bruta se verbose
    if verbose and "raw_response" in data:
        print("\n📋 Resposta da API:")
        print(json.dumps(data["raw_response"], indent=2, ensure_ascii=False))

    # Exibir metadados
    metadata = data.get("metadata", {})
    if metadata:
        print(f"\n📦 Módulo: {metadata.get('name', 'N/A')} v{metadata.get('version_stage', 'N/A')}")
        print(f"👥 Autor: {', '.join(metadata.get('author', []))}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
