# Processamento de Arquivos

Analisadores podem operar em arquivos configurando `data_type == "file"` e fornecendo `WorkerInput.filename`. Neste modo, `Analyzer.get_data()` retorna o caminho do arquivo.

## Padrão:

```python
from __future__ import annotations

from pathlib import Path

from sentineliqsdk import Analyzer, WorkerInput
from sentineliqsdk.models import AnalyzerReport


class FileHashAnalyzer(Analyzer):
    def execute(self) -> AnalyzerReport:
        filename = Path(self.get_data())  # caminho do arquivo
        data = filename.read_bytes()
        sha256 = __import__("hashlib").sha256(data).hexdigest()
        tax = self.build_taxonomy("info", "file", "sha256", sha256)
        return self.report({
            "filename": str(filename),
            "sha256": sha256,
            "taxonomy": [tax.to_dict()],
        })

    def run(self) -> AnalyzerReport:
        return self.execute()


if __name__ == "__main__":
    inp = WorkerInput(data_type="file", data=None, filename="/path/to/file")
    print(FileHashAnalyzer(inp).execute().full_report)
```

## Observações:

- Evite ler arquivos muito grandes diretamente na memória; utilize streaming quando aplicável.
- Respeite as restrições de TLP/PAP e não exfiltre conteúdo a menos que permitido.
- Quando `auto_extract` está habilitado, os IOCs encontrados no relatório completo são capturados como artefatos.
