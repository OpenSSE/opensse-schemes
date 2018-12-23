#!/bin/bash 

db_file="/Volumes/SSE_Bench/db_bench_1e6.dcdb"

kw_list=""
kKeywordGroupBase="Group-"
kKeywordRand10GroupBase=$kKeywordGroupBase"rand-10^"


# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124); #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeyword10GroupBase}1_${i}_${j}"
# 	done
# done
# echo $kw_list
# ./diana_client -q -b $db_file "$kw_list"
#
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124); #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeywordGroupBase}20_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
#
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124); #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeywordGroupBase}30_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
#
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124); #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeywordGroupBase}60_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
#
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124); #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeyword10GroupBase}2_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
#
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124); #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeyword10GroupBase}3_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
#
# for k in $(seq 0 3);
# do
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 11);
# 	do
# 		kw_list="$kw_list ${kKeyword10GroupBase}4_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
# done
#
# for k in $(seq 0 3);
# do
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 0);
# 	do
# 		kw_list="$kw_list ${kKeyword10GroupBase}5_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
# done
#
# 'Random' groups

# 1e2
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 103);
	do
		kw_list="$kw_list ${kKeywordRand10GroupBase}2_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

# 1e3
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 103);
	do
		kw_list="$kw_list ${kKeywordRand10GroupBase}3_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

#1e4
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 9); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordRand10GroupBase}4_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

# 1e5
for k in $(seq 0 9);
do
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 0); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordRand10GroupBase}5_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"
done

# # 1e6
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in `seq 0 104`; #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeywordRand10GroupBase}4_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"

	# echo $kw_list