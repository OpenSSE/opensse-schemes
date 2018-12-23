#!/bin/bash 

db_file="/Volumes/SSE_Bench/db_bench_1e6.dcdb"

kw_list=""
kKeywordGroupBase="Group-"
kKeyword10GroupBase=$kKeywordGroupBase"10^"


for i in $(seq 0 7);
do
	for j in $(seq 0 124); #total number is 1000
	do
		kw_list="$kw_list ${kKeyword10GroupBase}1_${i}_${j}"
	done
done

./diana_client -q -b $db_file "$kw_list"

kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 124); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordGroupBase}20_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 124); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordGroupBase}30_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 124); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordGroupBase}60_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 124); #total number is 1000
	do
		kw_list="$kw_list ${kKeyword10GroupBase}2_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 124); #total number is 1000
	do
		kw_list="$kw_list ${kKeyword10GroupBase}3_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

for k in $(seq 0 3);
do
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 11);
	do
		kw_list="$kw_list ${kKeyword10GroupBase}4_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"
done

for k in $(seq 0 3);
do
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 0);
	do
		kw_list="$kw_list ${kKeyword10GroupBase}5_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"
done


	# echo $kw_list