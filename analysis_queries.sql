select *
from cybersecurity_attacks

--what is the monthly yearly trend in total events and high severity events specially
select count(*) as total_events,
       count(*) filter (where severity_level='High') as high_severity,
	   ROUND(
        100.0 * COUNT(*) FILTER (WHERE severity_level = 'High') / COUNT(*), 2
    ) AS high_severity_pct
from cybersecurity_attacks
group by year_month
order by year_month
	
--what attack type is the most frequent within each network segment and does this vary by protocol
with ranked as
(
select network_segment,
       attack_type,
	   count(*) as freq,
	   rank() over(partition by network_segment order by count(*) desc) as rnk
from cybersecurity_attacks	
group by network_segment,attack_type
)
select network_segment,attack_type,freq
from ranked
where rnk=1


--what proportion of high serverity events were blocked vs logged vs ignored? where is the response gap largest
select count(*) filter(where severity_level='High' and action_taken='Blocked') as Blocked_proportion,
       count(*) filter(where severity_level='High' and action_taken='Logged') as Logged_proportion,
	   count(*) filter(where severity_level='High' and action_taken='Ignored') as Ignored_proportion,
	   ROUND(100.0*count(*) filter(where severity_level='High' and action_taken='Blocked')/count(*) filter(where severity_level='High'),2) as Blocked_pct,
       ROUND(100.0*count(*) filter(where severity_level='High' and action_taken='Logged')/count(*) filter(where severity_level='High'),2) as Logged_pct,
       ROUND(100.0*count(*) filter(where severity_level='High' and action_taken='Ignored')/count(*) filter(where severity_level='High'),2) as Ignored_pct
from cybersecurity_attacks


--which source destination  port combinations shows the highest average anomaly score
select source_port,destination_port,round(avg(anomaly_scores),2) as highest_avg_anomaly_score
from cybersecurity_attacks
group by source_port,destination_port
order by avg(anomaly_scores) desc

--how does the Detection coverage score correlate with the action taken - are poorly monitored events more likely to be ignored
select action_taken,
       round(avg(detection_coverage_score),2) as avg_score
from cybersecurity_attacks
group by action_taken;

select detection_coverage_score as score,
       count(*) filter(where action_taken='Ignored') as ignored_cnt,
       round(100.0*count(*) filter(where action_taken='Ignored')/count(*),2) as ignored_pct
from cybersecurity_attacks
group by detection_coverage_score
order by score;



--what are the top 10 highest anomaly score events and what do they have in common(traffic type,protocol,segment
with top10 as
(
select traffic_type,protocol,network_segment,anomaly_scores
from cybersecurity_attacks
order by anomaly_scores desc
limit 10
)

select traffic_type,count(*) from top10 group by traffic_type
union all
select protocol,count(*) from top10 group by protocol
union all
select network_segment,count(*) from top10 group by network_segment



--rank attack signatures by frequenct within each attack type using window functions
with cte as
(
select attack_signature,
       attack_type,
       count(*) as freq,
	   row_number() over(partition by attack_type order by count(*) desc) as rank_
from cybersecurity_attacks
group by attack_signature,attack_type
)
select *
from cte
order by attack_type,rank_







