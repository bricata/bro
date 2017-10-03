
export {
    # Function for testing domain membership
    global is_subdomain: function(name: string): bool;

    # Pattern for holding the domain regular expression
    global dl_regex: pattern &redef;

    # Container for lower-level domains of interest. 
    const notable_domains: set[string] = {
            "google.com",
            "youtube.com",
            "facebook.com",
            "yahoo.com",
            "wikipedia.org",
            "twitter.com",
            "amazon.com",
            "live.com",
            "linkedin.com"
    } &redef;
}

function is_notable_subdomain(name: string): bool
    {
    # Is the notable domain pattern found in the name?
    return dl_regex in name;
    }

event bro_init()
    {
    # Convert the set to a pattern, match top-level 
    # and all sub-domains.  
    dl_regex = set_to_regex(notable_domains, "(^\\.?|\\.)(~~)$");
    }
