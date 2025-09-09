# SentinelIQ SDK - Regras de Desenvolvimento

Este diretório contém as regras de desenvolvimento organizadas de forma sequencial e profissional para o SentinelIQ SDK.

## Estrutura Organizada

### 📋 1. Fundamentos Core
- **`01-fundamentos-core.mdc`** - Conceitos fundamentais, configuração e segurança

### 🔍 2. Desenvolvimento de Módulos
- **`02-desenvolvimento-analyzers.mdc`** - Padrões para desenvolvimento de Analyzers
- **`03-desenvolvimento-responders.mdc`** - Padrões para desenvolvimento de Responders
- **`04-desenvolvimento-detectores.mdc`** - Padrões para desenvolvimento de Detectores
- **`05-desenvolvimento-messaging.mdc`** - Padrões para Producers, Consumers e Pipelines

### 📚 3. Documentação e Qualidade
- **`06-exemplos-documentacao.mdc`** - Requisitos para exemplos e documentação
- **`07-workflow-desenvolvimento.mdc`** - Workflow de desenvolvimento e ferramentas
- **`08-commits-automaticos.mdc`** - Regras obrigatórias para commits automáticos por agentes

## ⚠️ Regras Críticas de Configuração

### ❌ PROIBIDO
- **NUNCA** usar `os.environ` diretamente em módulos
- **NUNCA** hardcodar credenciais no código fonte
- **NUNCA** usar variáveis de ambiente para configuração específica de módulos

### ✅ OBRIGATÓRIO
- **SEMPRE** usar `WorkerConfig.secrets` para credenciais
- **SEMPRE** usar métodos `get_secret()` e `get_config()`
- **SEMPRE** seguir os padrões de configuração em `01-fundamentos-core.mdc`

## 🚀 Guia Rápido de Desenvolvimento

### Para Analyzers
1. Ler `01-fundamentos-core.mdc` para conceitos básicos
2. Seguir `02-desenvolvimento-analyzers.mdc` para implementação
3. Criar exemplos conforme `06-exemplos-documentacao.mdc`
4. Seguir workflow em `07-workflow-desenvolvimento.mdc`

### Para Responders
1. Ler `01-fundamentos-core.mdc` para conceitos básicos
2. Seguir `03-desenvolvimento-responders.mdc` para implementação
3. Criar exemplos conforme `06-exemplos-documentacao.mdc`
4. Seguir workflow em `07-workflow-desenvolvimento.mdc`

### Para Detectores
1. Ler `01-fundamentos-core.mdc` para conceitos básicos
2. Seguir `04-desenvolvimento-detectores.mdc` para implementação
3. Criar exemplos conforme `06-exemplos-documentacao.mdc`

### Para Messaging (Producers/Consumers/Pipelines)
1. Ler `01-fundamentos-core.mdc` para conceitos básicos
2. Seguir `05-desenvolvimento-messaging.mdc` para implementação
3. Criar exemplos conforme `06-exemplos-documentacao.mdc`

## 📖 Como Usar Este Guia

1. **Iniciantes**: Comece com `01-fundamentos-core.mdc`
2. **Desenvolvimento**: Siga a sequência numérica dos arquivos
3. **Referência Rápida**: Use este README para navegação
4. **Troubleshooting**: Consulte `07-workflow-desenvolvimento.mdc`

## 🔧 Ferramentas de Desenvolvimento

```bash
# Scaffolding de novos módulos
poe new-analyzer -- --name MeuAnalyzer
poe new-responder -- --name MeuResponder
poe new-detector -- --name MeuDetector

# Qualidade de código
poe lint    # Linting e formatação
poe test    # Testes com coverage
poe docs    # Documentação MkDocs
```

## 📋 Checklist Rápido

Para cada novo módulo:
- [ ] Seguir padrões de nomenclatura
- [ ] Usar `WorkerConfig.secrets` para credenciais
- [ ] Implementar `METADATA` obrigatório
- [ ] Criar exemplo executável
- [ ] Adicionar testes adequados
- [ ] Documentar no MkDocs
- [ ] Passar em `poe lint` e `poe test`
- [ ] **Realizar commit automático** seguindo `08-commits-automaticos.mdc`

---

> **💡 Dica**: Para informações detalhadas sobre configuração e exemplos, consulte os arquivos numerados em ordem sequencial. Cada arquivo contém informações específicas e exemplos práticos para facilitar o desenvolvimento.
