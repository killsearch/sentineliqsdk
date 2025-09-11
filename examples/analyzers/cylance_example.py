#!/usr/bin/env python3
"""Exemplo de uso do CylanceAnalyzer.

Este exemplo demonstra como usar o CylanceAnalyzer para analisar hashes SHA256
usando a API da Cylance.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Adicionar o diretório src ao path para importar o SDK
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from sentineliqsdk import WorkerConfig, WorkerInput
from sentineliqsdk.analyzers.cylance import CylanceAnalyzer


def main() -> None:
    """Função principal do exemplo."""
    parser = argparse.ArgumentParser(
        description="Exemplo de uso do CylanceAnalyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python cylance_example.py --data "a1b2c3d4e5f6..." --data-type hash --execute
  python cylance_example.py --data "$(cat hash.txt)" --data-type hash --execute

Configurações necessárias (secrets):
  cylance.tenant_id     - ID do tenant Cylance
  cylance.app_id        - ID da aplicação Cylance
  cylance.app_secret    - Secret da aplicação Cylance
  cylance.region        - Região da API Cylance

Nota: Este exemplo requer credenciais válidas da API Cylance.
        """,
    )

    # Argumentos de dados
    parser.add_argument(
        "--data",
        required=True,
        help="Hash SHA256 para analisar (64 caracteres)",
    )
    parser.add_argument(
        "--data-type",
        default="hash",
        help="Tipo de dados (padrão: hash)",
    )

    # Configurações de TLP/PAP
    parser.add_argument(
        "--tlp",
        type=int,
        default=2,
        choices=[0, 1, 2, 3],
        help="Traffic Light Protocol level (padrão: 2)",
    )
    parser.add_argument(
        "--pap",
        type=int,
        default=2,
        choices=[0, 1, 2, 3],
        help="Permissible Actions Protocol level (padrão: 2)",
    )

    # Configurações de credenciais
    parser.add_argument(
        "--tenant-id",
        help="Cylance Tenant ID (ou use variável de ambiente)",
    )
    parser.add_argument(
        "--app-id",
        help="Cylance App ID (ou use variável de ambiente)",
    )
    parser.add_argument(
        "--app-secret",
        help="Cylance App Secret (ou use variável de ambiente)",
    )
    parser.add_argument(
        "--region",
        help="Cylance Region (ou use variável de ambiente)",
    )

    # Portões de segurança (OBRIGATÓRIO)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Executar operações reais (obrigatório para execução)",
    )
    parser.add_argument(
        "--include-dangerous",
        action="store_true",
        help="Incluir operações perigosas (não aplicável para este analyzer)",
    )

    # Configurações de debug
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Exibir informações detalhadas",
    )

    args = parser.parse_args()

    # Verificação de modo dry-run
    if not args.execute:
        print("❌ Modo dry-run. Use --execute para operações reais.")
        print("\n📋 Configuração que seria usada:")
        print(f"   Data: {args.data}")
        print(f"   Data Type: {args.data_type}")
        print(f"   TLP: {args.tlp}")
        print(f"   PAP: {args.pap}")
        return

    # Validar hash SHA256
    if args.data_type == "hash" and len(args.data) != 64:
        print("❌ Erro: Apenas hashes SHA256 (64 caracteres) são suportados.")
        return

    try:
        # Configurar secrets
        secrets: dict[str, dict[str, str]] = {}
        if args.tenant_id or args.app_id or args.app_secret or args.region:
            secrets["cylance"] = {}
            if args.tenant_id:
                secrets["cylance"]["tenant_id"] = args.tenant_id
            if args.app_id:
                secrets["cylance"]["app_id"] = args.app_id
            if args.app_secret:
                secrets["cylance"]["app_secret"] = args.app_secret
            if args.region:
                secrets["cylance"]["region"] = args.region

        # Criar configuração do worker
        config = WorkerConfig(
            check_tlp=True,
            max_tlp=args.tlp,
            check_pap=True,
            max_pap=args.pap,
            auto_extract=True,
            secrets=secrets,
        )

        # Criar input do worker
        worker_input = WorkerInput(
            data_type=args.data_type,
            data=args.data,
            tlp=args.tlp,
            pap=args.pap,
            config=config,
        )

        if args.verbose:
            print("🔍 Iniciando análise Cylance...")
            print(f"   Hash: {args.data}")
            print(f"   Tipo: {args.data_type}")

        # Executar analyzer
        analyzer = CylanceAnalyzer(worker_input)
        result = analyzer.run()

        # Exibir resultados
        print("\n✅ Análise concluída!")
        print(f"\n📊 Resultado: {result.full_report.get('verdict', 'N/A').upper()}")

        if result.full_report.get("taxonomy"):
            for tax in result.full_report["taxonomy"]:
                print(f"   {tax['namespace']}: {tax['predicate']}")

        if args.verbose and hasattr(result, "full_report"):
            print("\n📋 Relatório completo:")
            import json

            print(json.dumps(result.full_report, indent=2, ensure_ascii=False))

        # Verificar se há informações de ameaça
        if (
            hasattr(result, "full_report")
            and "hashlookup" in result.full_report
            and result.full_report["hashlookup"] != "hash_not_found"
        ):
            hashlookup = result.full_report["hashlookup"]
            if "sample" in hashlookup:
                sample = hashlookup["sample"]
                print("\n🔍 Informações da amostra:")
                print(f"   Nome: {sample.get('sample_name', 'N/A')}")
                print(f"   Score Cylance: {sample.get('cylance_score', 'N/A')}")
                print(f"   Classificação: {sample.get('classification', 'N/A')}")
                print(f"   Assinado: {sample.get('signed', 'N/A')}")
                print(f"   Quarentena Global: {sample.get('global_quarantined', 'N/A')}")

            # Mostrar dispositivos afetados
            device_count = len([k for k in hashlookup if k != "sample"])
            if device_count > 0:
                print(f"\n🖥️  Dispositivos afetados: {device_count}")
                for key, device in hashlookup.items():
                    if key != "sample":
                        print(f"   - {device.get('name', 'N/A')} ({device.get('state', 'N/A')})")

    except KeyboardInterrupt:
        print("\n❌ Operação cancelada pelo usuário.")
    except Exception as e:
        print(f"❌ Erro durante a análise: {e!s}")
        if args.verbose:
            import traceback

            traceback.print_exc()


if __name__ == "__main__":
    main()
