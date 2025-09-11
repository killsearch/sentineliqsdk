#!/usr/bin/env python3

"""
Exemplo de uso do DomainMailSpfDmarcAnalyzer.

Este exemplo demonstra como usar o DomainMailSpfDmarcAnalyzer para verificar
a configuração de SPF e DMARC de domínios para análise de segurança de email.

Uso:
    python domain_mail_spf_dmarc_example.py --data "example.com" --data-type "domain" --execute
    python domain_mail_spf_dmarc_example.py --data "google.com" --data-type "fqdn" --execute
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Adicionar o diretório src ao path para importar o módulo
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.domain_mail_spf_dmarc import DomainMailSpfDmarcAnalyzer


def main():
    """Função principal do exemplo."""
    parser = argparse.ArgumentParser(
        description="Exemplo de uso do DomainMailSpfDmarcAnalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s --data "example.com" --data-type "domain" --execute
  %(prog)s --data "google.com" --data-type "fqdn" --execute
  %(prog)s --data "microsoft.com" --data-type "domain" --execute
""",
    )

    # Argumentos de dados (obrigatórios)
    parser.add_argument("--data", required=True, help="Domínio para analisar (domain ou fqdn)")
    parser.add_argument(
        "--data-type",
        required=True,
        choices=["domain", "fqdn"],
        help="Tipo de dados (domain ou fqdn)",
    )

    # Portões de segurança (OBRIGATÓRIO)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Executar análise real (sem este flag, apenas mostra configuração)",
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Incluir operações perigosas (não aplicável para este analyzer)",
    )

    # Argumentos opcionais
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Mostrar informações detalhadas"
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "summary"],
        default="summary",
        help="Formato de saída (padrão: summary)",
    )

    args = parser.parse_args()

    # Verificação de modo dry-run
    if not args.execute:
        print("🔍 Modo dry-run ativo. Use --execute para executar análise real.")
        print(f"📊 Dados: {args.data}")
        print(f"📋 Tipo: {args.data_type}")
        print("🎯 Analyzer: DomainMailSpfDmarcAnalyzer")
        print("\n💡 Este analyzer verifica:")
        print("   • Configuração SPF (Sender Policy Framework)")
        print("   • Configuração DMARC (Domain-based Message Authentication)")
        print("   • Classifica a segurança da configuração de email")
        return

    try:
        # Configurar input
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=2,
            check_pap=True,
            max_pap=2,
            auto_extract=True,
        )

        input_data = WorkerInput(
            data_type=args.data_type,
            data=args.data,
            config=config,
        )

        # Executar análise
        if args.verbose:
            print(f"🔍 Analisando {args.data_type}: {args.data}")
            print("📡 Verificando registros SPF e DMARC...")

        analyzer = DomainMailSpfDmarcAnalyzer(input_data)
        result = analyzer.run()

        # Mostrar resultados
        if args.output_format == "json":
            print(json.dumps(result.full_report, indent=2, ensure_ascii=False))
        else:
            print_summary(result.full_report, args.verbose)

    except Exception as e:
        print(f"❌ Erro durante análise: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def print_summary(report: dict, verbose: bool = False):
    """Imprime um resumo dos resultados."""
    observable = report.get("observable", "N/A")
    verdict = report.get("verdict", "unknown")

    # Emojis baseados no verdict
    verdict_emoji = {"safe": "✅", "suspicious": "⚠️", "malicious": "🚨", "info": "ℹ️"}.get(
        verdict, "❓"
    )

    print(f"\n{verdict_emoji} Resultado da Análise SPF/DMARC")
    print(f"📍 Domínio: {observable}")
    print(f"🎯 Verdict: {verdict.upper()}")

    # Mostrar taxonomias
    taxonomies = report.get("taxonomy", [])
    if taxonomies:
        print("\n📊 Configurações:")
        for tax in taxonomies:
            protocol = tax.get("predicate", "Unknown")
            value = tax.get("value", "Unknown")
            level = tax.get("level", "info")

            status_emoji = {"safe": "✅", "suspicious": "⚠️", "malicious": "❌", "info": "ℹ️"}.get(
                level, "❓"
            )

            status_text = "Configurado" if value == "yes" else "Não Configurado"
            print(f"   {status_emoji} {protocol}: {status_text}")

    # Mostrar detalhes se verbose
    if verbose:
        spf_info = report.get("spf", {})
        dmarc_info = report.get("dmarc", {})

        if spf_info:
            print("\n📧 Detalhes SPF:")
            if "error" in spf_info:
                print(f"   ❌ Erro: {spf_info['error']}")
            else:
                print("   ✅ Registro válido encontrado")
                if "record" in spf_info:
                    print(f"   📝 Registro: {spf_info['record']}")

        if dmarc_info:
            print("\n🔒 Detalhes DMARC:")
            if "error" in dmarc_info:
                print(f"   ❌ Erro: {dmarc_info['error']}")
            else:
                print("   ✅ Registro válido encontrado")
                if "record" in dmarc_info:
                    print(f"   📝 Registro: {dmarc_info['record']}")

    # Mostrar erro se houver
    if "error" in report:
        print(f"\n❌ Erro: {report['error']}")


if __name__ == "__main__":
    main()
