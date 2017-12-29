##!	file_stats uses Bro's SumStats Framework to track metrics
##!  about the types of files seen, what is being extracted 
##!  and and the affects data loss is having on the completeness 
##!  of analyzed files.  
##!
##!  On every summary_interval a collection of metrics are logged
##!  about each file type observed in the environment.  
##!	
##!		mime_type:  standard MIME identifier for the file type
##! 	file_count:  the number of files seen of this type  
##! 	extracted:  percentage of these files that we're extracted
##! 	missing_bytes:  percentage of these files that we're missing bytes
##! 	avg_bytes_missing:  average percentage of the file that was missing
##!		
##!		Note:: the last three fields are percentages represented as a double.    

##!		TODO -- Make switching from percentages to raw counts a redef'able option  

##!		author: Adam Pumphrey


@load base/frameworks/sumstats

module file_stats;

export {
	redef enum Log::ID += { LOG };

	# Record for logging file stats
	type Info: record {
		ts: time &log &optional;
		mime_type: string &log &optional;
 		file_count: count  &log &optional;
 		extracted: double &log &default=0.0;
 		missing_bytes: double &log &default=0.0;
 		avg_bytes_missing: double &log &default=0.0;
	};
	
	# Define how long stats are collected before being 
	# logged
	#
	#  redef this constant to adjust the reporting 
	#  frequency. 
	const summary_interval: interval = 1min &redef;

	# Write summary stats to the reporter log stream 
	# instead of a seperate file_stats stream
	# 
	# redef this constant to F (false) to use the file_stats 
	# log stream
	const log_to_reporter: bool = T &redef;

	# Event generated when file stats are logged 
	global log_file_stat: event(rec: Info);
}


event file_state_remove(f: fa_file) 
	{
	# Check for the file metadata record
	if ( ! f?$info || ! f$info?$mime_type ) {
		return;
	}

	# Count files by mime_type
	SumStats::observe("mime count", 
					  SumStats::Key($str=f$info$mime_type),
					  SumStats::Observation($num=1));

	#  Count files that we're extracted, by mime_type
	if ( f?$info && f$info?$extracted && |f$info$extracted| > 0 ) {
		SumStats::observe("extracted count", 
				  SumStats::Key($str=f$info$mime_type),
				  SumStats::Observation($num=1));		
	}
	
	# Is the file missing bytes?
	if ( f?$missing_bytes && f$missing_bytes > 0 ) {

		# Count files that we're missing bytes, by mime_type
		SumStats::observe("missing bytes", 
				  SumStats::Key($str=f$info$mime_type),
				  SumStats::Observation($num=1));

	 	# Calculate the percentage of bytes missing from the file
	 	if ( f?$total_bytes && f$missing_bytes > 0 ) {
	 		local miss_perc = ( f$missing_bytes + 0.0 ) / ( f$total_bytes + 0.0 ) * 100;

		 	# Collect the average number of bytes missing from files, by mime_type 
		 	SumStats::observe("average loss", 
					  SumStats::Key($str=f$info$mime_type),
					  SumStats::Observation($dbl=miss_perc));
	 	} 
	} 
}

function print_file_stats(ts: time, key: SumStats::Key, result: SumStats::Result) 
	{
 	# Bail if there is no key string 
 	if ( ! key?$str || |key$str| == 0 ) {
 		return;
 	}

 	if ( log_to_reporter ) {
		local log_string = "mime_type=%s    count=%d    extracted=%.2f%%    missing_bytes=%.2f%%    average_bytes_missing=%.2f%%";
 	}
 
 	# Initialize the record to be logged
  	local report = Info(
 		$ts = ts
 	);
 
 	# Store the mime_type
 	report$mime_type = key$str;
 
 	if ( "mime count" in result ) {

 		# Store the file count
 		report$file_count = double_to_count(result["mime count"]$sum);

 		# Calculate the precentage extracted
 		if ( "extracted count" in result ) {
 			report$extracted = (( result["extracted count"]$sum + 0.0 ) / ( report$file_count + 0.0 )) * 100;
 		}

 		# Calculate the percentage missing bytes
	 	if ( "missing bytes" in result ) {
	 		report$missing_bytes = (( result["missing bytes"]$sum + 0.0 ) / ( report$file_count + 0.0 )) * 100; 	
	 	}

	 	# Store the average number of missing bytes
	 	if ( "average loss" in result ) {
	 		report$avg_bytes_missing = result["average loss"]$average;
	 	}
	 }

	if ( log_to_reporter ) {
		Reporter::info(fmt(log_string, 
							report$mime_type,
							report$file_count,
							report$extracted,
							report$missing_bytes,
							report$avg_bytes_missing
						   ));
	}
	else if ( file_stats::LOG in Log::active_streams ) {
		Log::write(file_stats::LOG, report);
	}
 }
 
event bro_init() {
 	# Set up reducers
 	local r1: SumStats::Reducer = [$stream="mime count", $apply=set(SumStats::SUM)];
 	local r2: SumStats::Reducer = [$stream="extracted count", $apply=set(SumStats::SUM)];
 	local r3: SumStats::Reducer = [$stream="missing bytes", $apply=set(SumStats::SUM)];
 	local r4: SumStats::Reducer = [$stream="average loss", $apply=set(SumStats::AVERAGE)];
 
 	# Create the SumStat
 	SumStats::create( [$name="file stats",
                                 $epoch=summary_interval,
                                 $reducers=set(r1, r2, r3, r4),
                                 $epoch_result = print_file_stats
                         ] );


 	# Create the log stream 
    if ( ! log_to_reporter ) {
    	Log::create_stream(file_stats::LOG, [$columns=Info, $ev=log_file_stat, $path="file_stats"]);
    }
 	
}

