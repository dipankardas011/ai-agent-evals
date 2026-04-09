# dipankardas/compromised-prod-server

```
export OPENAI_API_BASE="http://192.168.1.18:8000/v1"
export OPENAI_API_KEY="local-dummy-key"
harbor run -p "./compromised-prod-server" \
    --agent terminus-2 \
    --model custom_openai/Qwen3.5-9B-Q5_K_M.gguf \
    --ak 'model_info:dict={"max_input_tokens": 131072, "max_output_tokens": 131072}'
```

Here's what you need. To spin up the environment and get a shell (just like the AI agent would see):

```shell
harbor task start-env -p "./compromised-prod-server" -i
```

This starts the containers and drops you into an interactive shell in the main container. You'll see exactly what the AI agent sees — same filesystem, same state. Poke around, try grep, ls, cat, check what's findable.

The -a flag (on by default) also copies solution/ and tests/ into the container, but the agent does NOT get those during a real run. To see the pure agent view without solution/tests:

```shell
harbor task start-env -p "./compromised-prod-server" -i --no-all
```
