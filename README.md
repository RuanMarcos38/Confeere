# CONFERE — orientação preventiva

FastAPI com cadastro, login, histórico privado e resposta imediata. Oferece checklist local e análise contextual com OpenAI Responses API. Para links públicos, usa web search e exibe apenas fontes retornadas como citações reais pela API. Não certifica lojas, não garante pagamentos e não possui revisão humana ou cobrança.

## EasyPanel

Serviço existente `r2rmarketingdigital/confeere`, repositório `RuanMarcos38/Confeere`, branch `main`, Dockerfile e porta 8000. Manter volume `confere_data` em `/data`, gravável por UID 10001. A atualização preserva tabelas e consultas anteriores; elas podem ser analisadas pelo próprio usuário após revisar o relato e consentir com envio à IA.

Variáveis obrigatórias: `SECRET_KEY` aleatório (32+ caracteres), `DB_PATH=/data/confere.sqlite3`, `SESSION_HTTPS_ONLY=true`, `BASE_URL=https://confeere.r2rmarketingdigital.com.br`.

IA: `OPENAI_MODEL=gpt-4.1-mini` e `AI_DAILY_LIMIT=30`. A chave pode ser fornecida como `OPENAI_API_KEY` por um gerenciador de segredos, ou como envelope AES-256-GCM em `OPENAI_KEY_ENCRYPTED` e chave base64 em `OPENAI_KEY_UNLOCK`. Envelope: nonce de 12 bytes + ciphertext + tag de 16 bytes, codificados em base64; AAD `confere-v1`. A cifra evita passar a chave da API em texto aberto pelo editor da implantação; os dois valores de configuração juntos continuam sendo secretos e devem ter o mesmo controle de acesso de qualquer credencial. Nunca incluir valores no GitHub ou logs.

Limites persistentes: 5 tentativas de IA por conta em 30 dias, intervalo de 60 segundos, limite global diário em UTC (30 por padrão da implantação) e até duas chamadas de ferramenta por análise. São limites de requisições, não um teto financeiro. Falhas do provedor também contam para limitar abuso/custos. Sem chave, quota ou disponibilidade, oferecer checklist identificado como sem IA. Nunca mostrar aprovação inventada.

`GET /health`: consulta o banco e informa versão e se há configuração de IA, sem chamar a API ou expor segredos. Não atesta saldo ou funcionamento do provedor.

## Segurança e privacidade

Sessões HttpOnly/Secure/SameSite, CSRF em toda mutação, consultas por proprietário, SQL parametrizado, HTML escapado, CSP sem scripts, limites persistentes de login/cadastro e chamadas de IA. Não há fetch arbitrário de URLs pelo servidor: somente a API oficial da OpenAI recebe o relato consentido. Queries/fragments de URLs são retirados antes do envio. `store=false` não equivale a retenção zero pelo provedor. Não enviar dados pessoais ou sensíveis.

Há exclusão individual de consulta com confirmação; não há exclusão de conta, recuperação de senha ou verificação de e-mail. Backup automatizado, restauração, políticas LGPD completas, proteção contra abuso de cadastro e auditoria independente continuam necessários antes de comercializar. Não ativar cobrança automaticamente.

## Testes

Em ambiente isolado, instalar `requirements.txt`, `httpx` e `pytest`; executar `python -m pytest test_app.py -q`. A suíte usa banco temporário e não chama provedores. Cobre cadastro/login/logout, CSRF, isolamento entre contas, XSS, persistência de consultas legadas, preservação em falhas e reserva concorrente do limite de IA. Validar também os cenários reais de relato vago, Pix urgente e link público em ambiente com chave autorizada, sem registrar segredos.
