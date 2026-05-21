local _M = {}

--_M.inspect = kong.log.inspect
--_M.debug = kong.log.debug
local debug       = function(i) return end
local inspect     = function(i) return end

--[[
    This function is used to call a model from OpenAI to generate a completion based on the given prompt.
    It returns the completion, usage, and error message if any.

    @param gpt_api_key string: The API key for the OpenAI GPT model.
    @param model string: The model to use for the completion (ex: gpt-4o-mini, gpt-4o, etc...).
    @param system_prompt string: The system prompt to use for the completion.
    @param user_prompt string: The user prompt to use for the completion.
    @param temperature number: The temperature (that in short, controls the randomness of the completion) to use for the completion (default: 0.1).
]]--
_M.llm_openai_chat_completion = function(self, gpt_api_key, model, system_prompt, user_prompt, temperature)
    if not gpt_api_key then
        return nil, nil, "GPT API key is required"
    end

    if not temperature then
        temperature = 0.1
    end

    local cjson = require "cjson"
    local httpc = require "resty.http"
    local http = httpc.new()
    
    local usage = {
        input_token  = 0,
        output_token = 0,
        cached_token = 0,
        total_token  = 0
    }

    local res, err = http:request_uri("https://api.openai.com/v1/chat/completions", {
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer " .. gpt_api_key
        },
        body = cjson.encode({
            model = model,
            messages = {
                {
                    role = "developer",
                    content = system_prompt
                },
                {
                    role = "user",
                    content = user_prompt
                }
            },
            stream = false,
            temperature = temperature
        })
    })

    if not res then
        return nil, usage, err
    end

    local body = cjson.decode(res.body)
    usage.input_token  = body.usage.prompt_tokens
    usage.output_token = body.usage.completion_tokens
    usage.cached_token = body.usage.prompt_tokens_details.cached_tokens
    usage.total_token  = body.usage.total_tokens

    return body.choices[1].message.content, usage, nil
end

