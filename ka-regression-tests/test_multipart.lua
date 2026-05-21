local full_path_lua_script = debug.getinfo(1, "S").source:sub(2)
local script_path = full_path_lua_script:match("(.*/)") or "./"
package.path = script_path .. '?.lua;' .. script_path .. '../kong/plugins/karna/modules/?.lua;' .. package.path

local Multipart = require("multipart")
local rmultipart = require("multipart_resty")
local kamultipart = require("ka_multipart")
local inspect = require("inspect")

local argparse  = require "argparse"

-- parse script arguments
local parser = argparse("script", "An example.")
parser:flag("-d --debug", "Enable debug output", false)
parser:flag("-u --unserialize", "From table to multipart function", false)
parser:option("-t --type", "Lua multipart lib to use", "kong")
parser:option("-b --boundary", "Set a custom boundary (default xxx)", "xxx")
parser:option("-n --testnum", "Run only the <num> test number", false)
local args = parser:parse()

if args.debug then
    kamultipart.debug = true
end

kamultipart.check_missing_boundary = true
kamultipart.check_wrong_boundary = true
kamultipart.check_duplicated_header = true
kamultipart.check_duplicated_content_disposition_param = true
kamultipart.check_duplicated_content_disposition_header = true
kamultipart.validate_header_name = true
kamultipart.validate_boundary = true
kamultipart.validate_param_value = true

-- generate 10MB of random data
local random_data = ""
print("Generating 10MB of random data")
for i=1,102400 do
    random_data = random_data .. "a"
end

local payloads = {
    {
        title = "File without content type",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field2\"; filename=\"example.txt\"\r\n\r\nvalue2\r\n--"..args.boundary.."--"
    },
    {
        title = "File with content type and value (no quotes)",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=field1\r\n\r\nvalue1\r\n--"..args.boundary.."\r\nContent-Disposition: form-data; name=field2; filename=example.txt\r\nContent-Type: text/plain\r\n\r\nvalue2\r\n--"..args.boundary.."--"
    },
    {
        title = "Duplicated content-disposition parameter",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"; name=\"foo\"\r\n\r\nvalue1\r\n--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field2\"; filename=\"example.txt\"; filename=\"example.php\"\r\n\r\nvalue2\r\n--"..args.boundary.."--"
    },
    {
        title = "Duplicated content-disposition parameter with different case",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field2\"; filename=\"example.txt\"; fiLEname=\"example.php\"\r\n\r\nvalue2\r\n--"..args.boundary.."--"
    },
    {
        title = "No filename",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1bis\r\n\n\r\n--"..args.boundary.."--"
    },
    {
        title ="Encoded new line",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--"..args.boundary.."%0d%0aContent-Disposition: form-data; name=\"field2\"%0d%0a%0d%0atest\r\n--"..args.boundary.."--"
    },
    {
        title = "End part confusion",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"; filename=\"asd.txt\"\r\n\r\nvalue1\r\n--"..args.boundary.."%0d%0aContent-Disposition: form-data; name=\"field2\"%0d%0a%0d%0atest\r\n--"..args.boundary.."--"
    },
    {
        title ="Encoded new line at the end",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1--"..args.boundary.."%0d%0aContent-Disposition: form-data; name=\"field2\"%0d%0a%0d%0atest\r\n--"..args.boundary.."--"
    },
    {
        title = "Message with 10MB file",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"file\"; filename=\"example.txt\"\r\nContent-Type: text/plain\r\n\r\n" .. random_data .. "\r\n--"..args.boundary.."--"
    },
    {
        title = "Wrong boundary",
        test = "--wrong1234\r\nContent-Disposition: form-data; name=\"file\"; filename=\"example.txt\"\r\nContent-Type: text/plain\r\n\r\nfoo\r\n--wrong1234--"
    },
    {
        title = "WordPress contact form",
        test = "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[fields][1]\"\r\n"..
        "\r\n"..
        "John\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[fields][2]\"\r\n"..
        "\r\n"..
        "johndoe@gmail.com\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[fields][3]\"\r\n"..
        "\r\n"..
        "test\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[fields][4]\"\r\n"..
        "\r\n"..
        "test\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[fields][5][]\"\r\n"..
        "\r\n"..
        "<p>terms and conditions accepted <a href=\"/privacy-policy/\" target=\"_blank\">Privacy Policy</a> *</p>\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[id]\"\r\n"..
        "\r\n"..
        "1392\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[author]\"\r\n"..
        "\r\n"..
        "1\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[post_id]\"\r\n"..
        "\r\n"..
        "21\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[submit]\"\r\n"..
        "\r\n"..
        "wpforms-submit\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"wpforms[token]\"\r\n"..
        "\r\n"..
        "8608d24de9ddce19d681e5af9ceec10d\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"action\"\r\n"..
        "\r\n"..
        "wpforms_submit\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"page_url\"\r\n"..
        "\r\n"..
        "https://www.example.com/contacts/\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"page_title\"\r\n"..
        "\r\n"..
        "Contacts\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"page_id\"\r\n"..
        "\r\n"..
        "21\r\n--"..args.boundary.."--"
    },
    {
        title = "Duplicated content-disposition header",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1\"\r\nContent-disposition: form-data; name=\"f2\"; filename=\"f2\"\r\nContent-Type: text/plain\r\n\r\nfile content\r\n--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"f3\"\r\nContent-disposition: form-data; name=\"f4\"\r\nContent-Type: text/plain\r\n\r\nfield value\r\n--"..args.boundary.."--"
    },
    {
        title = "Invalid header name (ending whitespace)",
        test = "--"..args.boundary.."\r\nInvalid-Header-Ending-With-Space : foobar\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1\"\r\n\r\n\r\nfile content\r\n--"..args.boundary.."--"
    },
    {
        title = "Invalid header name (invalid character)",
        test = "--"..args.boundary.."\r\nInvalid-Header-Invalid_Char: foobar\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1\"\r\n\r\n\r\nfile content\r\n--"..args.boundary.."--"
    },
    {
        title = "Invalid header name (syntax confusion)",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1\"\r\n\n\n\r\nfile content\r\n--"..args.boundary.."--"
    },
    {
        title = "Null byte in filename",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1.txt\0.php\"\r\n\r\nfile content\0\r\n--"..args.boundary.."--"
    },
    {
        title = "Null byte in filename (percent encoded)",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1.txt%00.php\"\r\n\r\nfile content%00\0\r\n--"..args.boundary.."--"
    },
    {
        title = "Null byte in filename (double percent encoded)",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1.txt%2500.php\"\r\n\r\nfile content%00\0\r\n--"..args.boundary.."--"
    },
    {
        title = "Null byte in filename (triple percent encoded)",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"f1\"; filename=\"f1.txt%252500.php\"\r\n\r\nfile content%00\0\r\n--"..args.boundary.."--"
    },
    {
        title = "Content Disposition without name parameter in header value",
        test = "--"..args.boundary.."\r\nContent-Disposition: form-data; filename=\"f1.txt\"\r\n\r\nfile content\r\n--"..args.boundary.."--"
    },
    {
        title = "should decode a multipart body with multiple file parts and missing and repeating filename",
        test = "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"files\"; filename=\"file1.txt\"\r\n"..
        "Content-Type: text/plain\r\n"..
        "\r\n"..
        "... contents of file1.txt ...\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"files\"; filename=\"file1.txt\"\r\n"..
        "Content-Type: text/plain\r\n"..
        "\r\n"..
        "... contents of file2.txt ...\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"files\";\r\n"..
        "Content-Type: text/plain\r\n"..
        "\r\n"..
        "... contents of file3.txt ...\r\n"..
        "--"..args.boundary.."\r\n"..
        "Content-Disposition: form-data; name=\"files\";\r\n"..
        "Content-Type: text/plain\r\n"..
        "\r\n"..
        "... contents of file4.txt ...\r\n"..
        "--"..args.boundary.."--"
    },
    {
        title = "boundary too long",
        test = "--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafoobar\r\n"..
        "Content-Disposition: form-data; name=\"files\"; filename=\"file1.txt\"\r\n"..
        "Content-Type: text/plain\r\n"..
        "\r\n"..
        "... contents of file1.txt ...\r\n"..
        "--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafoobar--",
        boundary = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafoobar"
    }
}

for testnum,t in ipairs(payloads) do
    if args.testnum and tonumber(args.testnum) ~= testnum then
        goto continue
    end

    local body = t.test

    if t.boundary then
        args.boundary = t.boundary
    end

    print("\n🚀 Start test ["..testnum.."]: \27[33m" .. t.title .. "\27[0m")
    if args.debug then
        print("--- PARSING BODY ---")
        print("\27[32m" .. body .. "\27[0m")
        print("--- END BODY -------\n\n")
    end


    if args.type == "kong" then
        local multipart_data = Multipart(body, "multipart/form-data; boundary="..args.boundary)
        print(inspect(multipart_data))
    end

    if args.type == "resty" then
        local p, err = rmultipart.new(body, "multipart/form-data; boundary="..args.boundary)
        if not p then
            print("failed to create parser: ", err)
        end

        print(inspect(p))
        print("---")
        while true do
            local part_body, name, mime, filename = p:parse_part()
            if not part_body and not mime and not filename then
                print("--- end of parts ---")
                break
            end

            print("part_body: ", tostring(part_body))
            print("name: ", tostring(name))
            print("mime: ", tostring(mime))
            print("filename: ", tostring(filename))
        end
    end

    if args.type == "ka" then
        local body = t.test

        local multipart_data, err = kamultipart:parse(body, "multipart/form-data; boundary="..args.boundary)
        if multipart_data then
            if args.debug then
                print(inspect(multipart_data))
            end

            if args.unserialize then
                local multipart_message, merr = kamultipart:table_to_multipart(multipart_data)
                if multipart_message then
                    print("--- FROM TABLE TO MULTIPART ---")
                    print("\27[32m"..multipart_message.."\27[0m")
                    print("--- END FROM TABLE TO MULTIPART ---")
                else
                    print("failed to convert table to multipart. " .. merr)
                end
            end
        else
            print("failed to parse multipart data. " .. err)
        end
    end

    if args.type == "fuzz-resty" then
        body = "--"..args.boundary.."\r\nContent-Disposition: form-data; name=\"field1\"; filename=\"asd.txt\"\r\n\r\nvalue1\r\n%REPLACE%--"..args.boundary.."foobar\r\n--"..args.boundary.."--"

        -- loops trough all ASCII character code
        for i=0,255 do
            print("Trying with character: "..string.char(i))
            
            local fuzzed_body = body:gsub("%%REPLACE%%", string.char(i))
            print("--- PARSING BODY ---")
            print("\27[32m" .. fuzzed_body .. "\27[0m")
            print("--- END BODY -------\n\n")
            
            local p, err = rmultipart.new(fuzzed_body, "multipart/form-data; boundary="..args.boundary)
            if not p then
                print("failed to create parser: ", err)
            end

            while true do
                local part_body, name, mime, filename = p:parse_part()
                if not part_body and not mime and not filename then
                    break
                end

                if part_body == "value1" then
                    print("found allowed character: " .. string.char(i))
                else
                    print(part_body)
                end
            end
        end
        break
    end

    ::continue::
end