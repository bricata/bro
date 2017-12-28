file_stats uses Bro's SumStats Framework to track metrics
about the types of files seen, what is being extracted 
and and the affects data loss is having on the completeness 
of analyzed files.  

On every summary_interval a collection of metrics are logged
about each file type observed in the environment.  
    
     mime_type:  standard MIME identifier for the file type
     file_count:  the number of files seen of this type  
     extracted:  percentage of these files that we're extracted
     missing_bytes:  percentage of these files that we're missing bytes
     avg_bytes_missing:  average percentage of the file that was missing
        
Note the last three fields are percentages represented in the form
of a double/float. 
