module Log;

export {
	# Container for disabled log streams
	const disabled_streams: set[Log::ID] = { Communication::LOG } &redef; 
}

event bro_init()
    {
    # Check each active stream
    for ( log in Log::active_streams ) 
		{
		# Is the stream in the disabled set?
		if ( log in disabled_streams ) 
			{
			# Disable the stream
    		Log::disable_stream(log);	
    		}	
		}	
    }



