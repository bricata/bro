
module smtp_filters;

export {
    # Define a function to be used for determining Email direction
    global sort_mail: function(id: Log::ID, path: string, rec: SMTP::Info): string;
}

# Use Site bifs to determine if the Email is incoming our outgoing
function sort_mail(id: Log::ID, path: string, rec: SMTP::Info): string
    {
    if (Site::is_local_addr(rec$id$orig_h) && ( ! Site::is_local_addr(rec$id$resp_h)))
        {
        # Return the name of the destination log stream
        return "outgoing_email";
        }
    else if ( ! Site::is_local_addr(rec$id$orig_h) && Site::is_local_addr(rec$id$resp_h) )
        {
        # Return the name of the destination log stream
        return "incoming_email";
        }
    }

event bro_init()
    {
    # Remove the default filter
    Log::remove_default_filter(SMTP::LOG);

    # Use sort_mail for the path function
    Log::add_filter(SMTP::LOG,
                    [$name = "email_sorter",
                     $path_func = sort_mail]);
    }
