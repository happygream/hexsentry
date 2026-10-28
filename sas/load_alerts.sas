/*---------------------------------------------------------------------------
  hexsentry -> SAS
  Loads the flat alert table from `hexsentry scan ... --csv alerts.csv` and
  summarises it. Works in SAS Studio on SAS Viya or SAS OnDemand for Academics:
  upload alerts.csv to your home folder first, or change the path below.
---------------------------------------------------------------------------*/

%let csv = ~/hexsentry/demo_alerts.csv;

filename alerts "&csv" encoding="utf-8";

data work.alerts;
    infile alerts dsd firstobs=2 truncover lrecl=32767;
    length id $12 rule $32 title $40 severity $8 user $64 src $64 prev_src $64
           first_seen last_seen $25 verdict $10 reason $2000 evidence $4000;
    input id rule title severity confidence user src prev_src first_seen last_seen
          duration_s suppressed verdict reason evidence;
    first_ts = input(first_seen, e8601dz20.);
    last_ts  = input(last_seen, e8601dz20.);
    format first_ts last_ts datetime19. confidence 4.2;
    sev_rank = whichc(severity, 'low', 'medium', 'high', 'critical');
    label first_ts = "First seen (UTC)" sev_rank = "Severity rank";
    drop first_seen last_seen;
run;

/* Ignore alerts an analyst marked benign */
data work.active;
    set work.alerts;
    where suppressed = 0;
run;

title "hexsentry alerts by rule and severity";
proc freq data=work.active order=data;
    tables rule*severity / norow nocol nopercent;
run;

title "Confidence by rule";
proc sgplot data=work.active;
    hbox confidence / category=rule;
    xaxis min=0 max=1 grid;
run;

title "Alert timeline";
proc sgplot data=work.active;
    scatter x=first_ts y=rule / group=severity markerattrs=(symbol=circlefilled size=11);
    xaxis grid;
    yaxis discreteorder=data;
run;

title "Why each alert fired";
proc print data=work.active noobs label;
    var first_ts severity confidence title user src reason;
run;

title;
