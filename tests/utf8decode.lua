local utf8encode = function(value)
    local new_value = string.gsub(value, "([\194-\244][\128-\191])", function(c)
        local byte = {string.byte(c, 1, -1)}
        return string.format("%%u%04x", byte[1]*64+byte[2]-12416)
    end)
    return new_value
end

local utf8decode = function(value)
    -- example: utf8decode("%u0020") -> whitespace
    -- example: utf8decode("%uff1c") -> <
    local new_value = string.gsub(value, "%%u(%x%x%x%x)", function(c)
        return string.char(tonumber(c, 16))
    end)
end

local utf8FromHex = function(hex)
    -- Rimuove il simbolo '%' all'inizio se presente
    local cleanHex = hex:gsub("%%u", "")

    -- Converte l'hex in un numero intero
    local code = tonumber(cleanHex, 16)

    -- Controllo dell'input
    if not code then
        error("Input non valido")
    end

    -- Conversione del punto di codice Unicode in sequenza UTF-8
    if code < 0x80 then
        -- Punto di codice a 1 byte (0xxxxxxx)
        return string.char(code)
    elseif code < 0x800 then
        -- Punto di codice a 2 byte (110xxxxx 10xxxxxx)
        return string.char(
            0xC0 + math.floor(code / 0x40),
            0x80 + (code % 0x40)
        )
    elseif code < 0x10000 then
        -- Punto di codice a 3 byte (1110xxxx 10xxxxxx 10xxxxxx)
        return string.char(
            0xE0 + math.floor(code / 0x1000),
            0x80 + (math.floor(code / 0x40) % 0x40),
            0x80 + (code % 0x40)
        )
    elseif code < 0x110000 then
        -- Punto di codice a 4 byte (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
        return string.char(
            0xF0 + math.floor(code / 0x40000),
            0x80 + (math.floor(code / 0x1000) % 0x40),
            0x80 + (math.floor(code / 0x40) % 0x40),
            0x80 + (code % 0x40)
        )
    else
        error("Punto di codice non valido")
    end

end

local hexFromUTF8 = function(utf8char)
    local bytes = {utf8char:byte(1, -1)}
    local codepoint = nil
    
    if #bytes == 1 then
        -- Carattere 1-byte (0xxxxxxx)
        codepoint = bytes[1]
    elseif #bytes == 2 then
        -- Carattere 2-byte (110xxxxx 10xxxxxx)
        codepoint = (bytes[1] - 0xC0) * 0x40 + (bytes[2] - 0x80)
    elseif #bytes == 3 then
        -- Carattere 3-byte (1110xxxx 10xxxxxx 10xxxxxx)
        codepoint = (bytes[1] - 0xE0) * 0x1000 + (bytes[2] - 0x80) * 0x40 + (bytes[3] - 0x80)
    elseif #bytes == 4 then
        -- Carattere 4-byte (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
        codepoint = (bytes[1] - 0xF0) * 0x40000 + (bytes[2] - 0x80) * 0x1000 + (bytes[3] - 0x80) * 0x40 + (bytes[4] - 0x80)
    else
        error("Sequenza UTF-8 non valida o non supportata")
    end
    
    return string.format("%%u%04x", codepoint)
end

--print(utf8encode("æ"))

print(utf8FromHex("%uff1c"))
print(hexFromUTF8("€"))
--print(utf8decode("%u0020"))
--print(utf8decode("%uff1e"))