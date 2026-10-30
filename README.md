# CONFERE — lançamento técnico inicial

Serviço FastAPI para segunda opinião preventiva. Contém cadastro, login, sessão segura, envio de consultas, histórico e limite de 5 consultas por 30 dias. **Não possui pagamentos, avaliações automáticas, equipe de revisão ou funcionalidades familiares completas.** Não publicar como produto comercial sem auditoria, LGPD, políticas, testes e atendimento humano definido.

## EasyPanel

Fonte GitHub: `RuanMarcos38/Confeere` branch `main`; build `Dockerfile`; porta `8000`. Variáveis: `SECRET_KEY` (segredo longo aleatório), `DB_PATH=/data/confere.sqlite3`, `SESSION_HTTPS_ONLY=true`, `BASE_URL=https://confeere.r2rmarketingdigital.com.br`. Montar volume persistente em `/data` com permissão de escrita para UID 10001. Configurar domínio com HTTPS e DNS A para IP da VPS. Endpoint `/health`. Não habilitar publicação antes de confirmar HTTPS, backup, logs e retenção de dados.

## Execução local

`docker build -t confere .`

`docker run --rm -p 8000:8000 -e SECRET_KEY=segredo-aleatorio-com-mais-de-trinta-e-dois-caracteres -e SESSION_HTTPS_ONLY=false -v confere_data:/data confere`

A ausência de `SECRET_KEY` válido interrompe o início por segurança. Não inserir credenciais no GitHub.
