local _M = {}

kong = {
    request = {
        get_header = function(h) end
    },
    response = {
        get_header = function(h) end
    },
    log = {
        debug = function(m) end,
    },
    
    service = {
        response = {
            get_headers = function() end
        }
    }
}

ngx = {
    re = {},
    timer = {
        at = function(p, f) end
    },
    req = {
        get_headers = function() end
    },
    var = {
        request_uri = ""
    }
}

return _M