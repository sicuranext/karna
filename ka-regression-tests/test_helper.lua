local _M = {}

-- Create a custom loader that sets up the environment before loading
_M.setup_environment = function()
    -- Set up robust global mocks before any modules are loaded
    _G.kong = {
        request = {
            get_header = function(h) return nil end,
            get_headers = function() return {} end,
            get_raw_body = function() return "" end,
            get_method = function() return "GET" end,
            get_http_version = function() return "1.1" end
        },
        response = {
            get_header = function(h) return nil end,
            get_headers = function() return {} end,
            get_status = function() return 200 end
        },
        service = {
            response = {
                get_headers = function() return {} end,
                get_status = function() return 200 end
            },
            request = {
                set_raw_body = function() end
            }
        },
        log = {
            debug = function(m) end,
            inspect = function(t) end,
            err = function(m) end
        },
        router = {
            get_service = function() return { id = "123", name = "test_service" } end,
            get_route = function() return { id = "123", name = "test_route" } end
        },
        mocked = true
    }
    
    --[[_G.ngx = {
        re = {
            match = function() return nil end,
            gmatch = function() return function() return nil end end
        },
        unescape_uri = function(s) return s end,
        var = {
            remote_addr = "127.0.0.1",
            remote_port = "12345",
            server_addr = "127.0.0.1",
            server_port = "8000",
            request_id = "12345",
            server_id = "12345",
            request_uri = "/"
        }
    }]]--
    
    print("Global environment set up successfully")
end

-- Custom loader for the body parser
_M.init_body_parser = function()
    -- First set up the environment
    _M.setup_environment()
    
    -- Create a sandbox with our globals to load the module
    local function load_in_sandbox()
        -- We need to make sure kong is a global before loading the module
        assert(_G.kong, "Kong global variable not set")
        assert(_G.ngx, "NGX global variable not set")
        
        -- Force reload by clearing package cache
        package.loaded["ka_body_parser"] = nil
        
        -- Now we can safely require the module
        local body_parser = require("ka_body_parser")
        
        -- Set debug functions for testing
        body_parser.debug = function(m) print("[DEBUG] " .. tostring(m)) end
        body_parser.inspect = function(t) 
            print("[INSPECT]")
            for k, v in pairs(t) do
                print("  " .. tostring(k) .. ": " .. tostring(v))
            end
        end
        
        return body_parser
    end
    
    -- Load the module in our sandbox
    local success, result = pcall(load_in_sandbox)
    
    if not success then
        print("Error loading ka_body_parser: " .. tostring(result))
        return nil
    end
    
    print("Body parser module loaded successfully")
    return result
end

return _M