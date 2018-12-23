#!/bin/bash 

db_file="/Volumes/SSE_Bench/db_bench_1e8.dcdb"

kw_list=""
kKeywordGroupBase="Group-"
# kKeyword10GroupBase=$kKeywordGroupBase"10^"
kKeywordRand10GroupBase=$kKeywordGroupBase"rand-10^"


# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124); #total number is 1000
# 	do
# 		kw_list="$kw_list ${kKeyword10GroupBase}1_${i}_${j}"
# 	done
# done
#
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
# kw_list=""
# for i in $(seq 0 7);
# do
# 	for j in $(seq 0 124);
# 	do
# 		kw_list="$kw_list ${kKeyword10GroupBase}4_${i}_${j}"
# 	done
# done
# ./diana_client -q -b $db_file "$kw_list"
#
# kw_list=""
# for i in $(seq 0 7);
# do
#         for j in $(seq 0 124);
#         do
#                 kw_list="$kw_list ${kKeyword10GroupBase}5_${i}_${j}"
#         done
# done
# ./diana_client -q -b $db_file "$kw_list"

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
	for j in $(seq 0 103); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordRand10GroupBase}4_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

#1e5
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 103); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordRand10GroupBase}5_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

# 1e6
kw_list=""
for i in $(seq 0 7);
do
	for j in $(seq 0 9); #total number is 1000
	do
		kw_list="$kw_list ${kKeywordRand10GroupBase}6_${i}_${j}"
	done
done
./diana_client -q -b $db_file "$kw_list"

	# echo $kw_list
