module Log;

export {
    # Log ID's to enable JSON for
    const json_enabled: set[Log::ID] = set(Conn::LOG) &redef; 
}

event bro_init()
    {
    # Check all running streams
    for ( log_id in Log::active_streams ) 
        {
        # Is Log ID in enabled set? 
        if ( log_id in json_enabled )
            {
            # Load the default filter of the Log stream
            local filter = Log::get_filter(log_id, "default");

            # Create a new filter name, use the original as a base
            filter$name = cat(filter$name, "-json");

            # Specify a new stream path, use the original as a base
            filter$path = cat(filter$path, "-json");

            # Add the JSON Stream config options to the filter 
            filter$config = table(
                ["use_json"] = "T",
                ["json_timestamps"] = "JSON::TS_ISO8601");

            # Apply the modified default filter
            Log::add_filter(log_id, filter);              
            }
        }        
    }
