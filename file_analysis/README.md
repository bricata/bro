file_stats uses Bro's SumStats Framework to track metrics about the types of files seen, what is being extracted and and the affects data loss is having on the completeness of analyzed files.

On every summary_interval a collection of metrics are logged about each file type observed in the environment.

     mime_type:  standard MIME identifier for the file type
     file_count:  the number of files seen of this type  
     extracted:  percentage of these files that we're extracted
     missing_bytes:  percentage of these files that we're missing bytes
     avg_bytes_missing:  average percentage of the file that was missing
        

Note: The fields extracted, missing_bytes and avg_bytes_missing are precentages represented as a double. The file_stats log stream does not include the '%' sign.

Two redefinable options (shown below) are available to make adjusting behavior a little easier. The first, summary_interval, can be used to adjust how long summary statistics are gathered, and how often they are logged. The second, log_to_reporter, is a boolean for determining if file stats will be written to the reporter log or to a seperate log stream named file_stats. Simply changing this value to 'F' will create a seperate, customized log stream.  Only the format is different between the two options, the fields and values are the same.

    const summary_interval: interval = 1min &redef;
    const log_to_reporter: bool = T &redef;
 
