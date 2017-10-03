#  Include certain fields in a log stream
event bro_init()
    {
    # Load the default filter for the HTTP log stream
    local f = Log::get_filter(HTTP::LOG, "default");

    # Define a set of field names for the include field
    f$include = set("ts", "id.orig_h", "host", "uri");

    # Add the modified default filter back to the HTTP log
    Log::add_filter(HTTP::LOG, f);  
    }
