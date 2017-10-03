# Remove fields from a log stream 
event bro_init()
    {
    # Remove the default filter
    Log::remove_default_filter(SMTP::LOG);

    # Add a new filter, specify the exclude argument to remove a field
    Log::add_filter(SMTP::LOG, [$name="no_smtp_recips", $exclude=set("rcptto")]);  
    }
